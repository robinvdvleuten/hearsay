package postscout

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeResolver answers DNS from maps keyed like _caldavs._tcp.example.org.
type fakeResolver struct {
	srv map[string][]*net.SRV
	txt map[string][]string
}

func (r fakeResolver) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	key := "_" + service + "._" + proto + "." + name
	if records, ok := r.srv[key]; ok {
		return key, records, nil
	}
	return "", nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

func (r fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if records, ok := r.txt[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

// response is what the fake web answers for "METHOD https://host/path".
type response struct {
	status   int
	location string
	body     string
}

// newOptions sends every HTTPS request, whatever its host, to a local server
// that answers from routes, and records the requests it saw.
func newOptions(t *testing.T, resolver fakeResolver, routes map[string]response) (Options, *[]string) {
	t.Helper()
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " https://" + r.Host + r.URL.RequestURI()
		seen = append(seen, key)
		route, ok := routes[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if route.location != "" {
			w.Header().Set("Location", route.location)
		}
		w.WriteHeader(route.status)
		_, _ = w.Write([]byte(route.body))
	}))
	t.Cleanup(server.Close)

	return Options{Resolver: resolver, Transport: toServer(server)}, &seen
}

// toServer sends every connection, whatever its host, to a local TLS server.
func toServer(server *httptest.Server) http.RoundTripper {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // Local test server.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
}

func autoconfigXML(server string) string {
	return `<?xml version="1.0"?>
<clientConfig version="1.1"><emailProvider id="example.org"><domain>example.org</domain>` + server + `</emailProvider></clientConfig>`
}

const sslServer = `<incomingServer type="imap"><hostname>imap.%EMAILDOMAIN%</hostname><port>993</port><socketType>SSL</socketType><username>%EMAILLOCALPART%</username></incomingServer>`

func TestDiscoverCalDAVPresetAsksNobody(t *testing.T) {
	tests := map[string]string{
		"me@mailbox.org":  "https://dav.mailbox.org/",
		"me@fastmail.com": "https://caldav.fastmail.com/",
		"me@posteo.de":    "https://posteo.de:8443/",
		"me@POSTEO.NET":   "https://posteo.de:8443/",
	}

	for email, want := range tests {
		t.Run(email, func(t *testing.T) {
			d, seen := newOptions(t, fakeResolver{}, nil)

			found, err := DiscoverCalDAV(t.Context(), email, d)
			if err != nil {
				t.Fatalf("discover: %v", err)
			}

			if found.URL != want {
				t.Errorf("url = %q, want %q", found.URL, want)
			}
			if len(*seen) != 0 {
				t.Errorf("sent requests %v, want none", *seen)
			}
		})
	}
}

func TestDiscoverCalDAVOrder(t *testing.T) {
	srv := map[string][]*net.SRV{"_caldavs._tcp.example.org": {{Target: "dav.example.org.", Port: 8443}}}
	wellKnownRoutes := map[string]response{
		"GET https://example.org/.well-known/caldav": {status: http.StatusMovedPermanently, location: "https://cal.example.org/dav/"},
		"PROPFIND https://cal.example.org/dav/":      {status: http.StatusUnauthorized},
	}

	tests := []struct {
		name       string
		resolver   fakeResolver
		routes     map[string]response
		want       string
		wantSource Source
	}{
		{
			name:     "SRV with a TXT path",
			resolver: fakeResolver{srv: srv, txt: map[string][]string{"_caldavs._tcp.example.org": {"path=/caldav/"}}},
			routes: map[string]response{
				"PROPFIND https://dav.example.org:8443/caldav/": {status: http.StatusUnauthorized},
			},
			want:       "https://dav.example.org:8443/caldav/",
			wantSource: SourceDNS,
		},
		{
			name:     "SRV without a path asks the target's well-known URL",
			resolver: fakeResolver{srv: srv},
			routes: map[string]response{
				"GET https://dav.example.org:8443/.well-known/caldav": {status: http.StatusFound, location: "/dav/"},
				"PROPFIND https://dav.example.org:8443/dav/":          {status: http.StatusMultiStatus},
			},
			want:       "https://dav.example.org:8443/dav/",
			wantSource: SourceDNS,
		},
		{
			name:     "SRV on port 443 leaves the port out",
			resolver: fakeResolver{srv: map[string][]*net.SRV{"_caldavs._tcp.example.org": {{Target: "dav.example.org.", Port: 443}}}, txt: map[string][]string{"_caldavs._tcp.example.org": {"path=/"}}},
			routes: map[string]response{
				"PROPFIND https://dav.example.org/": {status: http.StatusUnauthorized},
			},
			want:       "https://dav.example.org/",
			wantSource: SourceDNS,
		},
		{
			name:       "well-known URL on the domain",
			routes:     wellKnownRoutes,
			want:       "https://cal.example.org/dav/",
			wantSource: SourceWellKnown,
		},
		{
			name:     "a dead SRV record falls through to the well-known URL",
			resolver: fakeResolver{srv: srv},
			routes:   wellKnownRoutes,
			want:     "https://cal.example.org/dav/",

			wantSource: SourceWellKnown,
		},
		{
			// Radicale's root sends GET to its web interface and answers PROPFIND.
			name: "a GET redirect past the DAV root isn't followed",
			routes: map[string]response{
				"GET https://example.org/.well-known/caldav": {status: http.StatusMovedPermanently, location: "/"},
				"GET https://example.org/":                   {status: http.StatusFound, location: "/.web/"},
				"PROPFIND https://example.org/":              {status: http.StatusUnauthorized},
				"PROPFIND https://example.org/.web/":         {status: http.StatusUnauthorized},
			},
			want:       "https://example.org/",
			wantSource: SourceWellKnown,
		},
		{
			name: "PROPFIND redirects are followed",
			routes: map[string]response{
				"GET https://example.org/.well-known/caldav": {status: http.StatusFound, location: "/dav"},
				"PROPFIND https://example.org/dav":           {status: http.StatusMovedPermanently, location: "/dav/"},
				"PROPFIND https://example.org/dav/":          {status: http.StatusMultiStatus},
			},
			want:       "https://example.org/dav/",
			wantSource: SourceWellKnown,
		},
		{
			name:       "SRV target of a dot means no service",
			resolver:   fakeResolver{srv: map[string][]*net.SRV{"_caldavs._tcp.example.org": {{Target: ".", Port: 0}}}},
			routes:     wellKnownRoutes,
			want:       "https://cal.example.org/dav/",
			wantSource: SourceWellKnown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _ := newOptions(t, tt.resolver, tt.routes)

			found, err := DiscoverCalDAV(t.Context(), "me@example.org", d)
			if err != nil {
				t.Fatalf("discover: %v", err)
			}

			if found.URL != tt.want {
				t.Errorf("url = %q, want %q", found.URL, tt.want)
			}
			if found.Source != tt.wantSource {
				t.Errorf("source = %q, want %q", found.Source, tt.wantSource)
			}
		})
	}
}

func TestDiscoverCalDAVFailures(t *testing.T) {
	tests := []struct {
		name   string
		routes map[string]response
	}{
		{"nothing there", nil},
		{"an ordinary website answers everything", map[string]response{
			"GET https://example.org/.well-known/caldav":      {status: http.StatusOK, body: "<html>"},
			"PROPFIND https://example.org/.well-known/caldav": {status: http.StatusMethodNotAllowed},
		}},
		{"redirect to plain HTTP", map[string]response{
			"GET https://example.org/.well-known/caldav": {status: http.StatusMovedPermanently, location: "http://example.org/dav/"},
			"PROPFIND http://example.org/dav/":           {status: http.StatusUnauthorized},
		}},
		{"redirect loop", map[string]response{
			"PROPFIND https://example.org/.well-known/caldav": {status: http.StatusFound, location: "/.well-known/caldav"},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _ := newOptions(t, fakeResolver{}, tt.routes)

			_, err := DiscoverCalDAV(t.Context(), "me@example.org", d)

			if !errors.Is(err, ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestDiscoverIMAPPresetAsksNobody(t *testing.T) {
	tests := map[string]string{
		"me@mailbox.org":  "imap.mailbox.org:993",
		"me@fastmail.com": "imap.fastmail.com:993",
		"me@posteo.de":    "posteo.de:993",
	}

	for email, want := range tests {
		t.Run(email, func(t *testing.T) {
			d, seen := newOptions(t, fakeResolver{}, nil)

			found, err := DiscoverIMAP(t.Context(), email, d)
			if err != nil {
				t.Fatalf("discover: %v", err)
			}

			if found.Addr != want || found.Security != SecurityTLS {
				t.Errorf("imap = %+v, want %q over TLS", found, want)
			}
			if len(*seen) != 0 {
				t.Errorf("sent requests %v, want none", *seen)
			}
		})
	}
}

func TestDiscoverIMAPOrder(t *testing.T) {
	const autoconfigURL = "GET https://autoconfig.example.org/mail/config-v1.1.xml"
	const wellKnownURL = "GET https://example.org/.well-known/autoconfig/mail/config-v1.1.xml"
	const ispdbURL = "GET https://autoconfig.thunderbird.net/v1.1/example.org"
	srv := map[string][]*net.SRV{"_imaps._tcp.example.org": {{Target: "srv.example.org.", Port: 993}}}

	tests := []struct {
		name         string
		resolver     fakeResolver
		routes       map[string]response
		wantAddr     string
		wantSecurity Security
		wantUsername string
		wantSource   Source
	}{
		{
			name: "autoconfig host comes first",
			routes: map[string]response{
				autoconfigURL: {status: http.StatusOK, body: autoconfigXML(sslServer)},
				wellKnownURL:  {status: http.StatusOK, body: autoconfigXML(`<incomingServer type="imap"><hostname>wrong.example.org</hostname><port>993</port><socketType>SSL</socketType></incomingServer>`)},
			},
			wantAddr:     "imap.example.org:993",
			wantSecurity: SecurityTLS,
			wantUsername: "me",
			wantSource:   SourceAutoconfig,
		},
		{
			name:         "well-known autoconfig is next",
			routes:       map[string]response{wellKnownURL: {status: http.StatusOK, body: autoconfigXML(sslServer)}},
			wantAddr:     "imap.example.org:993",
			wantSecurity: SecurityTLS,
			wantUsername: "me",
			wantSource:   SourceAutoconfig,
		},
		{
			name:         "ISPDB is next",
			resolver:     fakeResolver{srv: srv},
			routes:       map[string]response{ispdbURL: {status: http.StatusOK, body: autoconfigXML(sslServer)}},
			wantAddr:     "imap.example.org:993",
			wantSecurity: SecurityTLS,
			wantUsername: "me",
			wantSource:   SourceISPDB,
		},
		{
			name:         "then SRV",
			resolver:     fakeResolver{srv: srv},
			wantAddr:     "srv.example.org:993",
			wantSecurity: SecurityTLS,
			wantSource:   SourceDNS,
		},
		{
			name:         "then a guess",
			wantAddr:     "imap.example.org:993",
			wantSecurity: SecurityTLS,
			wantSource:   SourceGuess,
		},
		{
			name: "STARTTLS is kept",
			routes: map[string]response{autoconfigURL: {status: http.StatusOK, body: autoconfigXML(
				`<incomingServer type="imap"><hostname>imap.example.org</hostname><port>143</port><socketType>STARTTLS</socketType><username>%EMAILADDRESS%</username></incomingServer>`)}},
			wantAddr:     "imap.example.org:143",
			wantSecurity: SecurityStartTLS,
			wantUsername: "me@example.org",
			wantSource:   SourceAutoconfig,
		},
		{
			name: "plain servers are skipped for a secure one",
			routes: map[string]response{autoconfigURL: {status: http.StatusOK, body: autoconfigXML(
				`<incomingServer type="imap"><hostname>plain.example.org</hostname><port>143</port><socketType>plain</socketType></incomingServer>` +
					`<incomingServer type="pop3"><hostname>pop.example.org</hostname><port>995</port><socketType>SSL</socketType></incomingServer>` + sslServer)}},
			wantAddr:     "imap.example.org:993",
			wantSecurity: SecurityTLS,
			wantUsername: "me",
			wantSource:   SourceAutoconfig,
		},
		{
			name: "a file offering only plain IMAP is ignored",
			routes: map[string]response{autoconfigURL: {status: http.StatusOK, body: autoconfigXML(
				`<incomingServer type="imap"><hostname>plain.example.org</hostname><port>143</port><socketType>plain</socketType></incomingServer>`)}},
			wantAddr:     "imap.example.org:993",
			wantSecurity: SecurityTLS,
			wantSource:   SourceGuess,
		},
		{
			name:         "broken XML is ignored",
			routes:       map[string]response{autoconfigURL: {status: http.StatusOK, body: "<clientConfig"}},
			wantAddr:     "imap.example.org:993",
			wantSecurity: SecurityTLS,
			wantSource:   SourceGuess,
		},
		{
			name: "a bad hostname is ignored",
			routes: map[string]response{autoconfigURL: {status: http.StatusOK, body: autoconfigXML(
				`<incomingServer type="imap"><hostname>evil.example.org/path</hostname><port>993</port><socketType>SSL</socketType></incomingServer>`)}},
			wantAddr:     "imap.example.org:993",
			wantSecurity: SecurityTLS,
			wantSource:   SourceGuess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _ := newOptions(t, tt.resolver, tt.routes)

			found, err := DiscoverIMAP(t.Context(), "me@example.org", d)
			if err != nil {
				t.Fatalf("discover: %v", err)
			}

			if found.Addr != tt.wantAddr || found.Security != tt.wantSecurity {
				t.Errorf("imap = %+v, want %q %q", found, tt.wantAddr, tt.wantSecurity)
			}
			if found.Username != tt.wantUsername {
				t.Errorf("username = %q, want %q", found.Username, tt.wantUsername)
			}
			if found.Source != tt.wantSource {
				t.Errorf("source = %q, want %q", found.Source, tt.wantSource)
			}
		})
	}
}

func TestDiscoverIMAPCanSkipISPDB(t *testing.T) {
	d, seen := newOptions(t, fakeResolver{}, map[string]response{
		"GET https://autoconfig.thunderbird.net/v1.1/example.org": {status: http.StatusOK, body: autoconfigXML(sslServer)},
	})

	d.SkipISPDB = true

	found, err := DiscoverIMAP(t.Context(), "me@example.org", d)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	if found.Source == SourceISPDB {
		t.Error("used the ISPDB when told not to")
	}
	for _, request := range *seen {
		if strings.Contains(request, "thunderbird") {
			t.Errorf("sent %q, which tells Mozilla the domain", request)
		}
	}
}

func TestDiscoverNeverSendsTheEmailAddress(t *testing.T) {
	d, seen := newOptions(t, fakeResolver{}, nil)

	if _, err := DiscoverIMAP(t.Context(), "me@example.org", d); err != nil {
		t.Fatalf("discover imap: %v", err)
	}
	if _, err := DiscoverCalDAV(t.Context(), "me@example.org", d); !errors.Is(err, ErrNotFound) {
		t.Fatalf("discover caldav: %v", err)
	}

	if len(*seen) == 0 {
		t.Fatal("no requests seen")
	}
	for _, request := range *seen {
		if strings.Contains(request, "me@") || strings.Contains(request, "me%40") {
			t.Errorf("request %q contains the address", request)
		}
	}
}

func TestDiscoverRejectsBadDomains(t *testing.T) {
	for _, email := range []string{"me", "me@", "me@localhost", "me@exa_mple.org", "me@example.org/../evil", "me@[192.0.2.1]"} {
		t.Run(email, func(t *testing.T) {
			d, seen := newOptions(t, fakeResolver{}, nil)

			if _, err := DiscoverIMAP(t.Context(), email, d); !errors.Is(err, ErrNotFound) {
				t.Errorf("imap: err = %v, want ErrNotFound", err)
			}
			if _, err := DiscoverCalDAV(t.Context(), email, d); !errors.Is(err, ErrNotFound) {
				t.Errorf("caldav: err = %v, want ErrNotFound", err)
			}
			if len(*seen) != 0 {
				t.Errorf("sent requests %v, want none", *seen)
			}
		})
	}
}

func TestDiscoverStopsWhenCancelled(t *testing.T) {
	d, _ := newOptions(t, fakeResolver{}, nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := DiscoverIMAP(ctx, "me@example.org", d); !errors.Is(err, context.Canceled) {
		t.Errorf("imap: err = %v, want context.Canceled", err)
	}
	if _, err := DiscoverCalDAV(ctx, "me@example.org", d); !errors.Is(err, context.Canceled) {
		t.Errorf("caldav: err = %v, want context.Canceled", err)
	}
}

// plainHTTPAnswers is a web where a plain HTTP server would say all is well,
// so only the transport rule can stop discovery from settling on it.
type plainHTTPAnswers struct {
	location  string
	plainSeen *bool
}

func (p plainHTTPAnswers) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" {
		*p.plainSeen = true
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: http.NoBody, Request: req}, nil
	}
	header := http.Header{"Location": {p.location}}
	return &http.Response{StatusCode: http.StatusMovedPermanently, Header: header, Body: http.NoBody, Request: req}, nil
}

func TestDiscoverNeverFollowsARedirectToPlainHTTP(t *testing.T) {
	var plainSeen bool
	d := Options{
		Resolver:  fakeResolver{},
		Transport: plainHTTPAnswers{location: "http://example.org/dav/", plainSeen: &plainSeen},
	}

	_, err := DiscoverCalDAV(t.Context(), "me@example.org", d)

	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if plainSeen {
		t.Error("sent a request over plain HTTP")
	}
}

func TestAutoconfigNeverFollowsARedirectToPlainHTTP(t *testing.T) {
	var plainSeen bool
	d := Options{
		Resolver:  fakeResolver{},
		Transport: plainHTTPAnswers{location: "http://example.org/config.xml", plainSeen: &plainSeen},
	}

	found, err := DiscoverIMAP(t.Context(), "me@example.org", d)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	if found.Source != SourceGuess {
		t.Errorf("source = %q, want the guess", found.Source)
	}
	if plainSeen {
		t.Error("sent a request over plain HTTP")
	}
}

func TestDiscoverFindsBoth(t *testing.T) {
	d, _ := newOptions(t, fakeResolver{}, map[string]response{
		"GET https://autoconfig.example.org/mail/config-v1.1.xml": {status: http.StatusOK, body: autoconfigXML(sslServer)},
		"GET https://example.org/.well-known/caldav":              {status: http.StatusMovedPermanently, location: "https://cal.example.org/dav/"},
		"PROPFIND https://cal.example.org/dav/":                   {status: http.StatusUnauthorized},
	})

	result, err := Discover(t.Context(), "me@example.org", d)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	if result.IMAP.Addr != "imap.example.org:993" || result.IMAP.Source != SourceAutoconfig {
		t.Errorf("imap = %+v", result.IMAP)
	}
	if result.CalDAV == nil || result.CalDAV.URL != "https://cal.example.org/dav/" || result.CalDAV.Source != SourceWellKnown {
		t.Errorf("caldav = %+v", result.CalDAV)
	}
}

func TestDiscoverWithoutACalendarServer(t *testing.T) {
	d, _ := newOptions(t, fakeResolver{}, nil)

	result, err := Discover(t.Context(), "me@example.org", d)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	if result.IMAP.Source != SourceGuess {
		t.Errorf("imap source = %q, want the guess", result.IMAP.Source)
	}
	if result.CalDAV != nil {
		t.Errorf("caldav = %+v, want nil", result.CalDAV)
	}
}

func TestDiscoverErrors(t *testing.T) {
	d, _ := newOptions(t, fakeResolver{}, nil)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := Discover(t.Context(), "me@", d); !errors.Is(err, ErrNotFound) {
		t.Errorf("bad address: err = %v, want ErrNotFound", err)
	}
	if _, err := Discover(cancelled, "me@example.org", d); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err = %v, want context.Canceled", err)
	}
}

func TestTimeoutBoundsEachRequest(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	d := Options{
		Resolver:  fakeResolver{},
		Transport: toServer(server),
		Timeout:   50 * time.Millisecond,
	}

	start := time.Now()
	_, err := DiscoverCalDAV(t.Context(), "me@example.org", d)

	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v, want the 50ms timeout to end it", elapsed)
	}
}
