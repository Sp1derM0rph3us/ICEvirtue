// Package hostkey derives the key used to correlate a finding with the subdomain
// it belongs to.
//
// Nothing upstream agrees on a format. nuclei's matched-at is usually
// "https://a.example.com/wp-login.php" but can be "a.example.com:8443"; httpx
// emits "https://a.example.com"; the built-in fuzzer emits a full URL; subfinder
// emits a bare name; "dnsx -resp-only" emits a bare IP address; and mantra emits
// the literal string "mantra-discovery", which is not a host at all.
//
// Every one of those has to collapse to the same key when it means the same host,
// which is why both sides of the correlation go through Normalize. Consistency
// matters more here than canonicality: as long as the two sides agree, the join is
// right.
//
// This replaces an unanchored substring match performed in the browser
// (v.URL.includes(s.Domain)), which was both slow and wrong: a parent name is a
// substring of its children, so "a.example.com" absorbed every finding belonging
// to "sub.a.example.com", and "example.com" matched "http://notexample.com/"
// because the match was not restricted to the host component.
package hostkey

import (
	"net"
	"net/url"
	"strings"
)

// maxHostLen is the longest a DNS name may be, per RFC 1035.
const maxHostLen = 253

// Normalize reduces a tool-supplied value to its host, or returns "" when the
// value carries no usable host.
//
// A "" result is meaningful and must be preserved as SQL NULL rather than stored
// as an empty string: NULL never equals NULL, so a finding whose host could not be
// determined cannot be joined to anything by any query, instead of being joined to
// every other row that also failed to parse.
func Normalize(value string) string {
	s := strings.TrimSpace(value)
	if s == "" {
		return ""
	}

	// A bare IP literal has to be recognised before the promotion below, because an
	// unbracketed IPv6 address is not a valid URL authority: url.Parse reads
	// "2606:4700::1111" as a host followed by an invalid port and fails outright.
	//
	// This is also what makes Normalize idempotent for IPv6, which is load-bearing
	// rather than cosmetic — the key is returned unbracketed and then stored, and
	// that stored value comes back through this function as the host query
	// parameter when the dashboard scopes findings to one node.
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}

	// url.Parse only populates Host when the value has an authority component, so
	// a scheme-less value is promoted to a protocol-relative one.
	//
	// The test is "://" rather than "contains a colon" on purpose: to url.Parse,
	// "a.example.com:8443" is a perfectly well-formed scheme followed by an opaque
	// path, so testing for a colon would leave that value with an empty Host.
	if !strings.Contains(s, "://") && !strings.HasPrefix(s, "//") {
		s = "//" + s
	}

	u, err := url.Parse(s)
	if err != nil {
		return ""
	}

	// Hostname drops the port, drops any user:password prefix, and unwraps the
	// brackets around an IPv6 literal.
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))

	// An IP literal is a legitimate key: "dnsx -resp-only" puts bare addresses in
	// the subdomains table, and nuclei reports findings against them. Round-tripping
	// through net.IP canonicalises alternative spellings such as "::ffff:1.2.3.4",
	// so the two sides of a join cannot disagree on how the same address is written.
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}

	if !isHostname(host) {
		return ""
	}
	return host
}

// NormalizeOrNil is Normalize in the shape the models and the engine store.
// nil is the SQL NULL that keeps an uncorrelatable finding out of every join.
func NormalizeOrNil(value string) *string {
	host := Normalize(value)
	if host == "" {
		return nil
	}
	return &host
}

// isHostname reports whether host is a dotted DNS name.
//
// Requiring a dot is the load-bearing rule. It is what turns mantra's
// "mantra-discovery" placeholder into "no host" rather than into a host that
// findings would then be attributed to, and it is why a dotless name such as
// "localhost" is rejected — for an internet-facing recon tool that is the right
// answer, not a limitation.
//
// Known limitation: a Unicode (non-punycode) hostname is rejected, because
// accepting it correctly would mean taking on golang.org/x/net/idna for a case
// these tools essentially never emit. Already-encoded "xn--" hosts work fine.
func isHostname(host string) bool {
	if len(host) == 0 || len(host) > maxHostLen {
		return false
	}
	if !strings.Contains(host, ".") ||
		strings.HasPrefix(host, ".") ||
		strings.HasSuffix(host, ".") ||
		strings.Contains(host, "..") {
		return false
	}

	for i := 0; i < len(host); i++ {
		switch c := host[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			// Rejects amass's "*.example.com" wildcards, percent-escapes,
			// whitespace and every non-ASCII byte.
			return false
		}
	}
	return true
}
