package postscout

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// toLocal lets a plain HTTP server on this machine answer discovery's
// HTTPS-only requests for example.org. The server sees that host, and thinks
// it's on plain HTTP, so its redirects are put back to HTTPS.
type toLocal struct {
	addr string
}

func (l toLocal) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "example.org" {
		return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Request: req}, nil
	}
	req = req.Clone(req.Context())
	req.Host = "example.org"
	req.URL.Scheme = "http"
	req.URL.Host = l.addr
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if location := resp.Header.Get("Location"); location != "" {
		resp.Header.Set("Location", strings.Replace(location, "http://example.org", "https://example.org", 1))
	}
	return resp, nil
}

// radicale answers the way Radicale 3 does without a login: its well-known
// URL points at the root, whose GET goes to the web interface, and PROPFIND
// asks for a login.
func radicale(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/.well-known/caldav":
		http.Redirect(w, r, "http://example.org/", http.StatusMovedPermanently)
	case r.Method == "PROPFIND":
		w.WriteHeader(http.StatusUnauthorized)
	case r.URL.Path == "/":
		http.Redirect(w, r, "http://example.org/.web/", http.StatusFound)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

// baikal answers the way Baïkal does without a login: its well-known URL
// points at dav.php, which asks for a login.
func baikal(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/.well-known/caldav":
		http.Redirect(w, r, "http://example.org/dav.php", http.StatusMovedPermanently)
	case r.URL.Path == "/dav.php" && r.Method == "PROPFIND":
		w.WriteHeader(http.StatusUnauthorized)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

// pim-mcp's integration suite finds the real servers at these URLs. Here they
// are stand-ins that redirect the same way, so the tests need no Docker.
func TestDiscoveryFindsSelfHostedCalDAVServers(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{"radicale", radicale, "https://example.org/"},
		{"baikal", baikal, "https://example.org/dav.php"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			t.Cleanup(server.Close)
			d := Options{Resolver: fakeResolver{}, Transport: toLocal{server.Listener.Addr().String()}}

			found, err := DiscoverCalDAV(t.Context(), "tester@example.org", d)
			if err != nil {
				t.Fatalf("discover: %v", err)
			}

			if found.Source != SourceWellKnown {
				t.Errorf("source = %q", found.Source)
			}
			if found.URL != tt.want {
				t.Errorf("url = %q, want %q", found.URL, tt.want)
			}
		})
	}
}
