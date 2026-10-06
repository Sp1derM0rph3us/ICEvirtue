package engine

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/idna"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/hostkey"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

const directoryWorkers = 50
const directoryBodyLimit = 256 * 1024

type responseFingerprint struct {
	shape          string
	hash           [32]byte
	length, tokens int
	shingles       []uint64
	textual        bool
}
type directoryObservation struct {
	initial, terminal int
	fingerprint       responseFingerprint
	reason            string
	redirect          *models.RedirectObservation
}
type directoryObserver struct {
	client  *http.Client
	timeout time.Duration
}

func newDirectoryObserver() (*directoryObserver, func()) {
	tr := &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: directoryWorkers, IdleConnTimeout: 10 * time.Second}
	return &directoryObserver{client: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, timeout: 10 * time.Second}, tr.CloseIdleConnections
}
func redirectCode(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}
func directoryCode(code int) bool {
	return code == 200 || code == 403 || code == 405 || redirectCode(code)
}
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
func normalizedHostname(u *url.URL) string {
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(u.Hostname(), "."))
	if err != nil {
		return ""
	}
	return hostkey.Normalize(ascii)
}
func profileScope(host, domain string) bool {
	domain = hostkey.Normalize(domain)
	if net.ParseIP(domain) != nil {
		return host == domain
	}
	return domain != "" && (host == domain || strings.HasSuffix(host, "."+domain))
}

// Each observation has one deadline across the entire chain. Cross-host targets
// are recorded but never requested. No shared cookie jar is used.
func (o *directoryObserver) observe(ctx context.Context, original *url.URL, domain string, known map[string]bool) directoryObservation {
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	result := directoryObservation{}
	if original.User != nil || normalizedHostname(original) == "" {
		result.reason = "invalid_request"
		return result
	}
	current := *original
	seen := map[string]bool{}
	var chain []string
	for hops := 0; ; hops++ {
		if seen[current.String()] {
			result.reason = "redirect_loop"
			return result
		}
		seen[current.String()] = true
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			result.reason = "invalid_request"
			return result
		}
		req.Header.Set("User-Agent", "ICEvirtue-Fuzzer/1.0")
		resp, err := o.client.Do(req)
		if err != nil {
			result.reason = "request_failed"
			return result
		}
		if result.initial == 0 {
			result.initial = resp.StatusCode
		}
		result.terminal = resp.StatusCode
		chain = append(chain, fmt.Sprintf("%d", resp.StatusCode))
		if !redirectCode(resp.StatusCode) {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, directoryBodyLimit+1))
			resp.Body.Close()
			if readErr != nil {
				result.reason = "body_unreadable"
				return result
			}
			if len(body) > directoryBodyLimit {
				result.reason = "body_limit"
				return result
			}
			media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
			if media == "" {
				media, _, _ = mime.ParseMediaType(http.DetectContentType(body))
			}
			shape := strings.Join(chain, "|") + "|" + normalizeReflection(current.String(), original) + "|" + media
			result.fingerprint = makeFingerprint(shape, body, media, original)
			return result
		}
		resp.Body.Close()
		next, err := current.Parse(resp.Header.Get("Location"))
		if err != nil || resp.Header.Get("Location") == "" || normalizedHostname(next) == "" || next.User != nil || (next.Scheme != "http" && next.Scheme != "https") {
			result.reason = "invalid_redirect"
			return result
		}
		next.Fragment = ""
		chain = append(chain, normalizeReflection(next.String(), original))
		if normalizedHostname(next) != normalizedHostname(original) {
			kind := "cross_scope"
			if profileScope(normalizedHostname(next), domain) {
				kind = "cross_host"
			}
			result.redirect = &models.RedirectObservation{SourceURL: original.String(), DestinationURL: next.String(), DestinationHost: normalizedHostname(next), Kind: kind, PreviouslyEnumerated: known[normalizedHostname(next)], StatusCode: result.initial, ObservedAt: time.Now().UTC()}
			result.reason = kind
			return result
		}
		port := effectivePort(next)
		if (port != effectivePort(original) && port != "80" && port != "443") || (current.Scheme == "https" && next.Scheme == "http") {
			result.reason = "redirect_boundary"
			return result
		}
		if hops >= 5 {
			result.reason = "redirect_limit"
			return result
		}
		current = *next
	}
}

func normalizeReflection(s string, original *url.URL) string {
	values := []string{original.String(), original.EscapedPath(), original.Path}
	var variants []string
	for _, v := range values {
		if v == "" || v == "/" {
			continue
		}
		variants = append(variants, v, html.EscapeString(v))
		for i := 0; i < 2; i++ {
			v = url.QueryEscape(v)
			variants = append(variants, v)
		}
	}
	sort.Slice(variants, func(i, j int) bool { return len(variants[i]) > len(variants[j]) })
	for _, v := range variants {
		s = strings.ReplaceAll(s, v, "<requested>")
	}
	return s
}
func makeFingerprint(shape string, body []byte, media string, original *url.URL) responseFingerprint {
	textual := strings.HasPrefix(media, "text/") || strings.Contains(media, "json") || strings.Contains(media, "xml") || strings.Contains(media, "javascript")
	f := responseFingerprint{shape: shape, textual: textual}
	if !textual {
		f.hash = sha256.Sum256(body)
		f.length = len(body)
		return f
	}
	text := strings.Join(strings.Fields(normalizeReflection(string(body), original)), " ")
	f.hash = sha256.Sum256([]byte(text))
	f.length = len(text)
	words := strings.Fields(text)
	f.tokens = len(words)
	if len(words) >= 20 {
		unique := map[uint64]bool{}
		for i := 0; i+5 <= len(words); i++ {
			h := sha256.Sum256([]byte(strings.Join(words[i:i+5], " ")))
			unique[binary.LittleEndian.Uint64(h[:8])] = true
		}
		for h := range unique {
			f.shingles = append(f.shingles, h)
		}
		sort.Slice(f.shingles, func(i, j int) bool { return f.shingles[i] < f.shingles[j] })
	}
	return f
}
func fingerprintsMatch(a, b responseFingerprint) bool {
	if a.shape != b.shape {
		return false
	}
	if a.hash == b.hash {
		return true
	}
	if !a.textual || !b.textual || a.tokens < 20 || b.tokens < 20 || a.length == 0 || b.length == 0 {
		return false
	}
	if float64(min(a.length, b.length))/float64(max(a.length, b.length)) < .9 {
		return false
	}
	i, j, intersection := 0, 0, 0
	for i < len(a.shingles) && j < len(b.shingles) {
		if a.shingles[i] == b.shingles[j] {
			intersection++
			i++
			j++
		} else if a.shingles[i] < b.shingles[j] {
			i++
		} else {
			j++
		}
	}
	union := len(a.shingles) + len(b.shingles) - intersection
	return union > 0 && float64(intersection)/float64(union) >= .95
}
