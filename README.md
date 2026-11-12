# postscout

postscout is a Go package that finds a provider's IMAP and CalDAV servers from an email address, the way a mail client does when you set up an account. Your users type their address, and you get a mail server and a calendar server to show them, each with where it was found. It never follows a link to plain HTTP, never sends the email address anywhere, and lets you turn off the one lookup that tells a third party the domain.

> **Discovery answers are not to be trusted.** They come from DNS and websites, and an attacker may control either. Show the servers you found to the user, and get their confirmation before you send a password to them. Otherwise the password goes wherever an attacker said.

- **Many sources, in a fixed order.** Built-in presets for mailbox.org, Fastmail and Posteo, Thunderbird autoconfig files, Mozilla's ISPDB, DNS SRV and TXT records (RFC 6186 and RFC 6764) and the `/.well-known/caldav` URL. When nothing knows the mail server, it guesses `imap.<domain>:993` and says so.
- **Encrypted only.** Every URL it follows is HTTPS, a redirect to plain HTTP is refused, and only IMAP servers that use TLS or STARTTLS are returned. Plain HTTP is allowed to this machine only, for tests.
- **Lookups only.** No login is tried and the email address is never sent. Mozilla's ISPDB is asked for the domain, and `SkipISPDB` turns that off.
- **Says where each answer came from,** so you can tell the user that a server is a guess.
- **Bounded.** Each request has a timeout, redirects stop after five hops, and an autoconfig file is read up to 1 MiB.
- **Testable.** The DNS resolver and HTTP transport are yours to replace, and its own tests never touch the network.
- **No dependencies** outside the standard library.

```go
result, err := postscout.Discover(ctx, "jane@example.org", postscout.Options{})
if err != nil {
	return err
}
fmt.Println(result.IMAP.Addr, result.IMAP.Security, result.IMAP.Source)
if result.CalDAV != nil {
	fmt.Println(result.CalDAV.URL, result.CalDAV.Source)
}
// For a domain with an autoconfig file and a CalDAV SRV record, this prints:
// mail.example.org:993 tls provider's autoconfig file
// https://dav.example.org/caldav/ DNS SRV record
```

It was extracted from [pim-mcp](https://github.com/robinvdvleuten/pim-mcp), where it finds the servers when you add an account.

---

## Getting started

You need Go 1.26 or later.

```bash
go get github.com/robinvdvleuten/postscout
```

## Usage

`Discover` looks for both servers. It returns an error only for an address without a usable domain, or when the context ends. The mail server is always set, if need be by a guess. The calendar server is `nil` when nothing knew one.

If you already know one of the servers, ask for the other alone:

```go
imap, err := postscout.DiscoverIMAP(ctx, email, opts)
caldav, err := postscout.DiscoverCalDAV(ctx, email, opts)
```

`DiscoverCalDAV` returns an error wrapping `ErrNotFound` when it finds no server that answers WebDAV.

**Options.** The zero value uses the system's DNS and HTTP. Set `Resolver` or `Transport` to send lookups elsewhere, `SkipISPDB` to leave out Mozilla's ISPDB, and `Timeout` to change the five-second limit on each HTTP request. DNS lookups are bounded by the context.

**The order.** Mail: a preset, `autoconfig.<domain>`, the domain's `/.well-known/autoconfig` file, the ISPDB, an `_imaps._tcp` SRV record, then the guess. Calendar: a preset, a `_caldavs._tcp` SRV record with its TXT path, then the domain's `/.well-known/caldav`. The first source with a usable answer wins.

**What you get.** An IMAP address as `host:port` with its security mode, and a username when the autoconfig file names one. A CalDAV URL where the server answers WebDAV. The calendars themselves need a login to find, which is up to you.

---

## Limits

- **IMAP and CalDAV only.** No SMTP, CardDAV, POP3, Exchange or Microsoft's Autodiscover.
- **No OAuth.** It finds servers, and says nothing about how to log in to them.
- **Three presets.** Other providers are found through what their domain publishes, or the ISPDB.
- **Certificates are verified** by the transport you pass, or Go's default one. A self-signed certificate has to be trusted by the machine.

---

## Development

Install [mise](https://mise.jdx.dev), which fetches the pinned Go, linter and Vale, then set up the commit hook:

```bash
mise install && mise run setup
```

Check a change: formatting, tests, lint and known vulnerabilities.

```bash
mise run check
```

## License

Copyright 2026 Robin van der Vleuten

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

```
http://www.apache.org/licenses/LICENSE-2.0
```

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
