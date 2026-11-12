package hearsay

// preset holds the servers of a provider whose servers are known. Its IMAP
// server uses implicit TLS. Self-hosted servers need none, because they answer
// at their well-known URL.
type preset struct {
	imapAddr string
	caldav   string
}

var (
	mailboxOrg = preset{imapAddr: "imap.mailbox.org:993", caldav: "https://dav.mailbox.org/"}
	fastmail   = preset{imapAddr: "imap.fastmail.com:993", caldav: "https://caldav.fastmail.com/"}
	posteo     = preset{imapAddr: "posteo.de:993", caldav: "https://posteo.de:8443/"}
)

// presets maps email domains to providers. Customers' own domains aren't here,
// and are found through DNS instead.
var presets = map[string]preset{
	"mailbox.org":  mailboxOrg,
	"fastmail.com": fastmail,
	"fastmail.fm":  fastmail,
	"posteo.de":    posteo,
	"posteo.net":   posteo,
	"posteo.org":   posteo,
	"posteo.eu":    posteo,
	"posteo.at":    posteo,
	"posteo.ch":    posteo,
	"posteo.com":   posteo,
}
