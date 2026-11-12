// Package hearsay finds a provider's IMAP and CalDAV servers from an email
// address, the way a mail client does when you set up an account.
//
// It tries built-in presets, then what the domain publishes: Thunderbird
// autoconfig files, DNS SRV and TXT records (RFC 6186 and RFC 6764) and the
// /.well-known/caldav URL. Mozilla's ISPDB is asked for the domain only, and
// can be turned off. Every URL it follows must be HTTPS, plain HTTP is allowed
// to loopback only, and a redirect is held to the same rule.
//
// Discovery only looks things up. The email address itself is never sent, and
// no login is tried. The answers come from DNS and websites that an attacker
// may control, so show the servers to the user and get their confirmation
// before a password is sent to them.
package hearsay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Security is how an IMAP connection is encrypted.
type Security string

// IMAP security modes. Discovery never returns an unencrypted one.
const (
	SecurityTLS      Security = "tls"      // TLS from the first byte, usually port 993
	SecurityStartTLS Security = "starttls" // required STARTTLS, usually port 143
)

// Source says where discovery found a setting. Its value is a short phrase
// meant to be shown to the user next to the server.
type Source string

// Where discovery can find a setting.
const (
	SourcePreset     Source = "built-in preset"
	SourceDNS        Source = "DNS SRV record"
	SourceWellKnown  Source = "well-known URL"
	SourceAutoconfig Source = "provider's autoconfig file"
	SourceISPDB      Source = "Mozilla ISPDB"
	SourceGuess      Source = "a guess from the domain, please check it"
)

// DefaultTimeout bounds each HTTP request when Options.Timeout is zero.
const DefaultTimeout = 5 * time.Second

const (
	maxHops            = 5
	maxAutoconfigBytes = 1 << 20
	httpsPort          = 443
	implicitTLSPort    = "993"
)

// ErrNotFound means no source knew the service, or the email address has no
// domain that could be looked up.
var ErrNotFound = errors.New("could not be discovered")

var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// Resolver is the part of net.Resolver that discovery uses.
type Resolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Options changes how discovery looks things up. The zero value uses the
// system's DNS and HTTP, and asks Mozilla's ISPDB.
type Options struct {
	// Resolver answers DNS lookups. Nil means net.DefaultResolver.
	Resolver Resolver
	// Transport sends HTTP requests. Nil means http.DefaultTransport.
	// Redirects are handled by discovery, not by the transport.
	Transport http.RoundTripper
	// SkipISPDB leaves out Mozilla's ISPDB, which would learn the domain.
	SkipISPDB bool
	// Timeout bounds each HTTP request. Zero means DefaultTimeout. DNS lookups
	// are bounded by the context only.
	Timeout time.Duration
}

// IMAP is a discovered mail server.
type IMAP struct {
	// Addr is host:port.
	Addr     string
	Security Security
	// Username is the login the source suggested, or empty if it had no
	// opinion. The email address is the usual choice then.
	Username string
	Source   Source
}

// CalDAV is a discovered calendar server. URL is where the server answers
// WebDAV, not a calendar: finding the calendars needs a login.
type CalDAV struct {
	URL    string
	Source Source
}

// Result is what Discover found.
type Result struct {
	// IMAP is always set when Discover returns no error, if need be by a guess.
	IMAP IMAP
	// CalDAV is nil when no source knew a calendar server.
	CalDAV *CalDAV
}

// Discover finds both the mail and the calendar server for an email address.
// It returns an error only for an address without a usable domain, or when
// the context ends. Use DiscoverIMAP or DiscoverCalDAV when only one is needed.
func Discover(ctx context.Context, email string, opts Options) (Result, error) {
	imap, err := DiscoverIMAP(ctx, email, opts)
	if err != nil {
		return Result{}, err
	}
	result := Result{IMAP: imap}
	caldav, err := DiscoverCalDAV(ctx, email, opts)
	switch {
	case err == nil:
		result.CalDAV = &caldav
	case !errors.Is(err, ErrNotFound):
		return Result{}, err
	}
	return result, nil
}

func (o Options) resolver() Resolver {
	if o.Resolver != nil {
		return o.Resolver
	}
	return net.DefaultResolver
}

func (o Options) client(checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &http.Client{Transport: o.Transport, Timeout: timeout, CheckRedirect: checkRedirect}
}

// lookupSRV returns the best host and port for a service. net.Resolver sorts
// the records by priority.
func (o Options) lookupSRV(ctx context.Context, service, domain string) (string, error) {
	_, records, err := o.resolver().LookupSRV(ctx, service, "tcp", domain)
	if err != nil {
		return "", err
	}
	for _, record := range records {
		target := strings.ToLower(strings.TrimSuffix(record.Target, "."))
		// A target of "." says the service isn't offered (RFC 2782).
		if !hostnamePattern.MatchString(target) {
			continue
		}
		if record.Port == httpsPort {
			return target, nil
		}
		return net.JoinHostPort(target, strconv.Itoa(int(record.Port))), nil
	}
	return "", errors.New("no usable SRV record")
}

func emailDomain(email string) (string, error) {
	_, domain, ok := strings.Cut(email, "@")
	domain = strings.ToLower(domain)
	if !ok || !hostnamePattern.MatchString(domain) {
		return "", fmt.Errorf("servers for %q %w", email, ErrNotFound)
	}
	return domain, nil
}
