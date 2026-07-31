package hostkey

import "testing"

// TestNormalize covers the shapes each upstream tool actually emits. The point of
// the table is that every row on the left has to reach the same key as the other
// rows describing the same host, because that agreement is what the correlation
// join depends on.
func TestNormalize(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		// nuclei matched-at
		{"full url with path and query", "https://a.example.com/wp-login.php?x=1", "a.example.com"},
		{"url with fragment", "https://a.example.com/x#frag", "a.example.com"},
		{"http scheme", "http://a.example.com/", "a.example.com"},

		// httpx
		{"scheme and host only", "https://a.example.com", "a.example.com"},

		// subfinder / amass
		{"bare name", "a.example.com", "a.example.com"},
		{"apex", "example.com", "example.com"},
		{"deep name", "sub.a.example.com", "sub.a.example.com"},

		// normalization
		{"uppercase", "https://A.Example.COM/", "a.example.com"},
		{"trailing dot", "a.example.com.", "a.example.com"},
		{"explicit port", "a.example.com:8443", "a.example.com"},
		{"scheme and port", "https://a.example.com:8443/x", "a.example.com"},
		{"default port", "https://A.Example.COM.:443/", "a.example.com"},
		{"userinfo", "http://user:pw@a.example.com/", "a.example.com"},
		{"surrounding whitespace", "  a.example.com\t", "a.example.com"},
		{"underscore label", "_dmarc.example.com", "_dmarc.example.com"},
		{"punycode", "xn--80ak6aa92e.com", "xn--80ak6aa92e.com"},

		// dnsx -resp-only emits bare addresses, and nuclei reports against them
		{"ipv4", "1.2.3.4", "1.2.3.4"},
		{"ipv4 with scheme and port", "http://1.2.3.4:8080/admin", "1.2.3.4"},
		{"ipv6 bracketed with port", "https://[2606:4700::1111]:8443/x", "2606:4700::1111"},
		{"ipv6 canonicalised", "[2606:4700:0:0::1111]", "2606:4700::1111"},
		{"ipv4 mapped ipv6 canonicalised", "[::ffff:1.2.3.4]", "1.2.3.4"},
		// Bare, unbracketed IPv6 is what Normalize itself returns, so it must round
		// trip: this value comes back in as the host query parameter.
		{"bare unbracketed ipv6", "2606:4700::1111", "2606:4700::1111"},
		{"bare unbracketed ipv6 uppercase", "2606:4700::ABCD", "2606:4700::abcd"},
		{"bare unbracketed ipv6 long form", "2606:4700:0:0:0:0:0:1111", "2606:4700::1111"},

		// no usable host
		{"mantra placeholder", "mantra-discovery", ""},
		{"amass wildcard", "*.example.com", ""},
		{"dotless name", "localhost", ""},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"leading dot", ".example.com", ""},
		{"consecutive dots", "a..example.com", ""},
		{"non ascii", "exâmple.com", ""},
		{"space inside", "a b.example.com", ""},
		{"scheme only", "https://", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Normalize(c.input); got != c.want {
				t.Errorf("Normalize(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}

// TestNormalizeDoesNotMatchAnUnrelatedSuffix is the first half of the bug this
// package exists to fix. The old browser-side correlation searched the whole URL
// with an unanchored substring match, so a finding on notexample.com counted
// towards example.com, as did any URL with the name in its path or query.
func TestNormalizeDoesNotMatchAnUnrelatedSuffix(t *testing.T) {
	target := Normalize("example.com")

	for _, other := range []string{
		"http://notexample.com/",
		"https://evil.com/?next=example.com",
		"https://evil.com/example.com/path",
		"https://example.com.evil.com/",
	} {
		if got := Normalize(other); got == target {
			t.Errorf("Normalize(%q) = %q, which collides with the key for example.com", other, got)
		}
	}
}

// TestNormalizeDoesNotAbsorbDescendants is the second half. A parent name is a
// substring of every child name, so under the old match "a.example.com" silently
// took on every finding belonging to "sub.a.example.com" while the child showed
// only its own — and the apex, if enumerated, absorbed the entire profile.
func TestNormalizeDoesNotAbsorbDescendants(t *testing.T) {
	parent := Normalize("a.example.com")
	child := Normalize("sub.a.example.com")
	apex := Normalize("example.com")

	if parent == child {
		t.Errorf("parent %q and child %q share a key", parent, child)
	}
	if apex == parent || apex == child {
		t.Errorf("apex %q collides with %q or %q", apex, parent, child)
	}

	// The child's finding URL must key to the child, not the parent.
	if got := Normalize("https://sub.a.example.com/wp-login.php"); got != child {
		t.Errorf("a finding on the child keyed to %q, want %q", got, child)
	}
}

// TestNormalizeAgreesAcrossToolFormats states the invariant the join relies on:
// the same host described in every format each tool uses must produce one key.
func TestNormalizeAgreesAcrossToolFormats(t *testing.T) {
	want := "a.example.com"

	// Left to right: subfinder, httpx, nuclei matched-at, the fuzzer's dir URL,
	// gau/subjs JS source, and a host:port with no scheme.
	for _, form := range []string{
		"a.example.com",
		"https://a.example.com",
		"https://a.example.com/wp-login.php",
		"https://a.example.com/admin",
		"https://a.example.com/static/app.js?v=2",
		"a.example.com:8443",
	} {
		if got := Normalize(form); got != want {
			t.Errorf("Normalize(%q) = %q, want %q — the two sides of the join would disagree", form, got, want)
		}
	}
}

func TestNormalizeOrNil(t *testing.T) {
	if got := NormalizeOrNil("mantra-discovery"); got != nil {
		t.Errorf("NormalizeOrNil(%q) = %q, want nil so the row cannot be joined", "mantra-discovery", *got)
	}
	if got := NormalizeOrNil(""); got != nil {
		t.Errorf("NormalizeOrNil(\"\") = %q, want nil", *got)
	}

	got := NormalizeOrNil("https://a.example.com/x")
	if got == nil {
		t.Fatal("NormalizeOrNil returned nil for a usable host")
	}
	if *got != "a.example.com" {
		t.Errorf("NormalizeOrNil = %q, want %q", *got, "a.example.com")
	}
}

// TestNormalizeIsIdempotent matters because the value is written by a hook on
// insert, repaired on re-sighting, and backfilled by a migration. All three paths
// may see a value that has already been through Normalize.
func TestNormalizeIsIdempotent(t *testing.T) {
	for _, input := range []string{
		"https://a.example.com/x", "A.Example.COM.", "1.2.3.4",
		"[2606:4700:0:0::1111]", "mantra-discovery",
	} {
		once := Normalize(input)
		if twice := Normalize(once); twice != once {
			t.Errorf("Normalize(%q) = %q, but Normalize(%q) = %q", input, once, once, twice)
		}
	}
}
