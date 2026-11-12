package hearsay_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/robinvdvleuten/hearsay"
)

// offlineDNS stands in for a domain's DNS in these examples, so they need no
// network. It publishes a CalDAV server and its path, as RFC 6764 describes.
type offlineDNS struct{}

func (offlineDNS) LookupSRV(_ context.Context, service, _, name string) (string, []*net.SRV, error) {
	if service == "caldavs" && name == "example.org" {
		return "_caldavs._tcp.example.org.", []*net.SRV{{Target: "dav.example.org.", Port: 443}}, nil
	}
	return "", nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

func (offlineDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if name == "_caldavs._tcp.example.org" {
		return []string{"path=/caldav/"}, nil
	}
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

// offlineWeb stands in for the domain's websites: an autoconfig file, and a
// CalDAV server that asks for a login.
type offlineWeb struct{}

func (offlineWeb) RoundTrip(req *http.Request) (*http.Response, error) {
	status, body := http.StatusNotFound, ""
	switch req.Method + " " + req.URL.String() {
	case "GET https://autoconfig.example.org/mail/config-v1.1.xml":
		status, body = http.StatusOK, `<clientConfig version="1.1"><emailProvider id="example.org">
<incomingServer type="imap"><hostname>mail.example.org</hostname><port>993</port>
<socketType>SSL</socketType><username>%EMAILADDRESS%</username></incomingServer>
</emailProvider></clientConfig>`
	case "PROPFIND https://dav.example.org/caldav/":
		status = http.StatusUnauthorized
	}
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}

func ExampleDiscover() {
	result, err := hearsay.Discover(context.Background(), "jane@example.org", hearsay.Options{
		Resolver:  offlineDNS{},
		Transport: offlineWeb{},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Show these to the user, and ask before a password goes there.
	fmt.Printf("IMAP:   %s (%s), user %s, from the %s\n",
		result.IMAP.Addr, result.IMAP.Security, result.IMAP.Username, result.IMAP.Source)
	if result.CalDAV != nil {
		fmt.Printf("CalDAV: %s, from a %s\n", result.CalDAV.URL, result.CalDAV.Source)
	}
	// Output:
	// IMAP:   mail.example.org:993 (tls), user jane@example.org, from the provider's autoconfig file
	// CalDAV: https://dav.example.org/caldav/, from a DNS SRV record
}

func ExampleDiscoverIMAP() {
	// A provider with a built-in preset is answered without a single lookup.
	imap, err := hearsay.DiscoverIMAP(context.Background(), "jane@fastmail.com", hearsay.Options{})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(imap.Addr, imap.Security, imap.Source)
	// Output: imap.fastmail.com:993 tls built-in preset
}

func ExampleDiscoverCalDAV() {
	caldav, err := hearsay.DiscoverCalDAV(context.Background(), "jane@example.org", hearsay.Options{
		Resolver:  offlineDNS{},
		Transport: offlineWeb{},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(caldav.URL)
	// Output: https://dav.example.org/caldav/
}
