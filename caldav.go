package hearsay

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/robinvdvleuten/hearsay/internal/transport"
)

const wellKnownCalDAV = "/.well-known/caldav"

// DiscoverCalDAV tries a preset, then DNS (RFC 6764), then the domain's
// well-known URL. It returns an error wrapping ErrNotFound when none of them
// leads to a server that answers WebDAV.
func DiscoverCalDAV(ctx context.Context, email string, opts Options) (CalDAV, error) {
	domain, err := emailDomain(email)
	if err != nil {
		return CalDAV{}, err
	}
	if p, ok := presets[domain]; ok {
		return CalDAV{URL: p.caldav, Source: SourcePreset}, nil
	}

	if base, err := opts.caldavFromDNS(ctx, domain); err == nil {
		return CalDAV{URL: base, Source: SourceDNS}, nil
	}
	if err := ctx.Err(); err != nil {
		return CalDAV{}, err
	}
	if base, err := opts.davEndpoint(ctx, "https://"+domain+wellKnownCalDAV); err == nil {
		return CalDAV{URL: base, Source: SourceWellKnown}, nil
	}
	if err := ctx.Err(); err != nil {
		return CalDAV{}, err
	}
	return CalDAV{}, fmt.Errorf("CalDAV server for %s %w", domain, ErrNotFound)
}

func (o Options) caldavFromDNS(ctx context.Context, domain string) (string, error) {
	host, err := o.lookupSRV(ctx, "caldavs", domain)
	if err != nil {
		return "", err
	}
	path := wellKnownCalDAV
	// A missing TXT record is normal: the path is then the well-known one.
	records, _ := o.resolver().LookupTXT(ctx, "_caldavs._tcp."+domain)
	for _, record := range records {
		if value, ok := strings.CutPrefix(record, "path="); ok && strings.HasPrefix(value, "/") {
			path = value
		}
	}
	return o.davEndpoint(ctx, "https://"+host+path)
}

// davEndpoint finds where a DAV server answers. A well-known URL gets one GET,
// because some servers only redirect that. Following more would leave the DAV
// path: Radicale's root redirects GET to its web interface. From there on,
// PROPFIND follows redirects and tells a DAV server from a website that answers
// anything with a page.
func (o Options) davEndpoint(ctx context.Context, start string) (string, error) {
	current := start
	if strings.HasSuffix(start, wellKnownCalDAV) {
		_, next, err := o.probe(ctx, http.MethodGet, current)
		if err != nil {
			return "", err
		}
		if next != "" {
			current = next
		}
	}
	for range maxHops {
		status, next, err := o.probe(ctx, "PROPFIND", current)
		if err != nil {
			return "", err
		}
		if next != "" {
			current = next
			continue
		}
		if status != http.StatusMultiStatus && status != http.StatusUnauthorized {
			return "", fmt.Errorf("not a DAV server: status %d", status)
		}
		return current, nil
	}
	return "", errors.New("too many redirects")
}

// probe sends one request and reports where a redirect points, if it does.
func (o Options) probe(ctx context.Context, method, target string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Depth", "0")
	client := o.client(func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	})
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return resp.StatusCode, "", nil
	}
	location, err := req.URL.Parse(resp.Header.Get("Location"))
	if err != nil {
		return 0, "", err
	}
	if err := transport.CheckURL(location); err != nil {
		return 0, "", err
	}
	return resp.StatusCode, location.String(), nil
}
