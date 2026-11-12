package hearsay

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/robinvdvleuten/hearsay/internal/transport"
)

// DiscoverIMAP tries a preset, the provider's autoconfig file, Mozilla's ISPDB
// unless Options.SkipISPDB is set, DNS (RFC 6186), and finally guesses
// imap.<domain> on port 993. So it finds something for any valid domain, and
// returns an error only for an address without one, or when the context ends.
func DiscoverIMAP(ctx context.Context, email string, opts Options) (IMAP, error) {
	domain, err := emailDomain(email)
	if err != nil {
		return IMAP{}, err
	}
	if p, ok := presets[domain]; ok {
		return IMAP{Addr: p.imapAddr, Security: SecurityTLS, Source: SourcePreset}, nil
	}

	sources := []struct {
		url    string
		source Source
	}{
		{"https://autoconfig." + domain + "/mail/config-v1.1.xml", SourceAutoconfig},
		{"https://" + domain + "/.well-known/autoconfig/mail/config-v1.1.xml", SourceAutoconfig},
	}
	if !opts.SkipISPDB {
		sources = append(sources, struct {
			url    string
			source Source
		}{"https://autoconfig.thunderbird.net/v1.1/" + url.PathEscape(domain), SourceISPDB})
	}
	for _, source := range sources {
		if found, ok := opts.fetchAutoconfig(ctx, source.url, email); ok {
			found.Source = source.source
			return found, nil
		}
		if err := ctx.Err(); err != nil {
			return IMAP{}, err
		}
	}

	if host, err := opts.lookupSRV(ctx, "imaps", domain); err == nil {
		return IMAP{Addr: host, Security: SecurityTLS, Source: SourceDNS}, nil
	}
	if err := ctx.Err(); err != nil {
		return IMAP{}, err
	}
	return IMAP{
		Addr:     net.JoinHostPort("imap."+domain, implicitTLSPort),
		Security: SecurityTLS,
		Source:   SourceGuess,
	}, nil
}

// fetchAutoconfig reports false on any failure: a missing or broken file just
// means trying the next source.
func (o Options) fetchAutoconfig(ctx context.Context, target, email string) (IMAP, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return IMAP{}, false
	}
	client := o.client(func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxHops {
			return errors.New("too many redirects")
		}
		return transport.CheckURL(req.URL)
	})
	resp, err := client.Do(req)
	if err != nil {
		return IMAP{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return IMAP{}, false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAutoconfigBytes))
	if err != nil {
		return IMAP{}, false
	}
	return parseAutoconfig(data, email)
}

// parseAutoconfig reads Thunderbird's autoconfig format, taking the first IMAP
// server that encrypts its connection.
func parseAutoconfig(data []byte, email string) (IMAP, bool) {
	var config struct {
		Servers []struct {
			Type     string `xml:"type,attr"`
			Hostname string `xml:"hostname"`
			Port     int    `xml:"port"`
			Socket   string `xml:"socketType"`
			Username string `xml:"username"`
		} `xml:"emailProvider>incomingServer"`
	}
	if err := xml.Unmarshal(data, &config); err != nil {
		return IMAP{}, false
	}

	local, domain, _ := strings.Cut(email, "@")
	expand := strings.NewReplacer("%EMAILADDRESS%", email, "%EMAILLOCALPART%", local, "%EMAILDOMAIN%", domain)
	for _, server := range config.Servers {
		var security Security
		switch strings.ToUpper(server.Socket) {
		case "SSL":
			security = SecurityTLS
		case "STARTTLS":
			security = SecurityStartTLS
		default:
			continue
		}
		host := strings.ToLower(expand.Replace(server.Hostname))
		if server.Type != "imap" || !hostnamePattern.MatchString(host) || server.Port < 1 || server.Port > 65535 {
			continue
		}
		return IMAP{
			Addr:     net.JoinHostPort(host, strconv.Itoa(server.Port)),
			Security: security,
			Username: expand.Replace(server.Username),
		}, true
	}
	return IMAP{}, false
}
