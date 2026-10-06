package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type directoryRoundTrip func(*http.Request) (*http.Response, error)

func (f directoryRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testObserver(fn directoryRoundTrip) *directoryObserver {
	return &directoryObserver{client: &http.Client{Transport: fn, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, timeout: time.Second}
}
func testResponse(code int, body, location string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Content-Type": []string{"text/plain"}, "Location": []string{location}}}
}
func parsedURL(t *testing.T, value string) *url.URL {
	t.Helper()
	u, e := url.Parse(value)
	if e != nil {
		t.Fatal(e)
	}
	return u
}

func TestDirectoryClassification(t *testing.T) {
	for _, kind := range []string{"soft_200", "blanket_403", "blanket_405", "login", "home", "real", "canonical", "unstable", "oversized", "missing"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int64
			observer := testObserver(func(r *http.Request) (*http.Response, error) {
				n := requests.Add(1)
				switch kind {
				case "soft_200":
					return testResponse(200, "Missing resource: "+r.URL.Path, ""), nil
				case "blanket_403":
					return testResponse(403, "Forbidden", ""), nil
				case "blanket_405":
					return testResponse(405, "Method not allowed", ""), nil
				case "login":
					if r.URL.Path == "/login" {
						return testResponse(200, "Login form", ""), nil
					}
					return testResponse(303, "", "/login?redirect_to="+url.QueryEscape(r.URL.Path)), nil
				case "home":
					if r.URL.Path == "/" {
						return testResponse(200, "Welcome", ""), nil
					}
					return testResponse(308, "", "/"), nil
				case "real":
					if r.URL.Path == "/admin" {
						return testResponse(200, "Administrative application", ""), nil
					}
					return testResponse(404, "Missing: "+r.URL.Path, ""), nil
				case "canonical":
					if !strings.HasSuffix(r.URL.Path, "/") {
						return testResponse(301, "", r.URL.Path+"/"), nil
					}
					if r.URL.Path == "/admin/" {
						return testResponse(200, "Administrative application", ""), nil
					}
					return testResponse(404, "Not found", ""), nil
				case "unstable":
					return testResponse(200, fmt.Sprintf("Different response %d", n), ""), nil
				case "oversized":
					return testResponse(200, strings.Repeat("x", directoryBodyLimit+1), ""), nil
				default:
					return testResponse(410, "Gone", ""), nil
				}
			})
			obs, assessment, reason, _ := classifyDirectory(context.Background(), observer, newBaselineCache(2), parsedURL(t, "http://x.example.com/admin"), "example.com", nil)
			expected := "unknown"
			if kind == "real" || kind == "canonical" {
				expected = "confirmed"
			}
			if kind == "missing" {
				expected = ""
			}
			if assessment != expected {
				t.Fatalf("assessment=%s reason=%s observation=%+v", assessment, reason, obs)
			}
			if kind == "login" && reason != "matches_missing_paths" {
				t.Fatal("reflected login redirect not recognized", reason)
			}
		})
	}
}
func TestDirectoryRedirectBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, location, domain, reason string
		known                          bool
	}{
		{"known", "https://y.example.com/login", "example.com", "cross_host", true},
		{"unseen", "https://y.example.com/login", "example.com", "cross_host", false},
		{"external", "https://microsoft.com/login", "example.com", "cross_scope", false},
		{"narrow", "https://y.example.com/login", "x.example.com", "cross_scope", true},
		{"suffix", "https://evilexample.com/login", "example.com", "cross_scope", false},
		{"port", "http://x.example.com:9000/login", "example.com", "redirect_boundary", false},
		{"invalid", "javascript:alert(1)", "example.com", "invalid_redirect", false},
		{"credentials", "https://user:pass@x.example.com/login", "example.com", "invalid_redirect", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			observer := testObserver(func(r *http.Request) (*http.Response, error) { calls++; return testResponse(302, "", tc.location), nil })
			obs := observer.observe(context.Background(), parsedURL(t, "http://x.example.com/admin"), tc.domain, map[string]bool{"y.example.com": tc.known})
			if calls != 1 || obs.reason != tc.reason {
				t.Fatalf("calls=%d observation=%+v", calls, obs)
			}
			if strings.HasPrefix(tc.reason, "cross_") {
				if obs.redirect == nil || obs.redirect.PreviouslyEnumerated != tc.known || obs.redirect.SourceURL != "http://x.example.com/admin" {
					t.Fatalf("wrong attribution: %+v", obs.redirect)
				}
			}
		})
	}
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			calls := 0
			observer := testObserver(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Scheme == "http" {
					return testResponse(code, "", "https://x.example.com/admin/"), nil
				}
				return testResponse(200, "Real", ""), nil
			})
			obs := observer.observe(context.Background(), parsedURL(t, "http://x.example.com/admin"), "example.com", nil)
			if obs.reason != "" || obs.initial != code || obs.terminal != 200 || calls != 2 {
				t.Fatal(obs, calls)
			}
		})
	}
}
func TestDirectoryObserverLimits(t *testing.T) {
	observer := testObserver(func(r *http.Request) (*http.Response, error) { return testResponse(302, "", r.URL.Path), nil })
	if obs := observer.observe(context.Background(), parsedURL(t, "http://x.example.com/admin"), "example.com", nil); obs.reason != "redirect_loop" {
		t.Fatal(obs)
	}
	observer = testObserver(func(r *http.Request) (*http.Response, error) { return testResponse(302, "", r.URL.Path+"/next"), nil })
	if obs := observer.observe(context.Background(), parsedURL(t, "http://x.example.com/admin"), "example.com", nil); obs.reason != "redirect_limit" {
		t.Fatal(obs)
	}
	observer = testObserver(func(r *http.Request) (*http.Response, error) {
		return testResponse(302, "", "http://x.example.com/admin"), nil
	})
	if obs := observer.observe(context.Background(), parsedURL(t, "https://x.example.com/admin"), "example.com", nil); obs.reason != "redirect_boundary" {
		t.Fatal(obs)
	}
	observer = testObserver(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	observer.timeout = 10 * time.Millisecond
	if obs := observer.observe(context.Background(), parsedURL(t, "http://x.example.com/admin"), "example.com", nil); obs.initial != 0 || obs.reason != "request_failed" {
		t.Fatal(obs)
	}
}
func TestBaselineIsolationSharingAndEviction(t *testing.T) {
	cache := newBaselineCache(2)
	var controls atomic.Int64
	observer := testObserver(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "icevirtue-missing-") {
			controls.Add(1)
			time.Sleep(time.Millisecond)
		}
		return testResponse(200, "Application "+r.URL.Host, ""), nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, assessment, _, _ := classifyDirectory(context.Background(), observer, cache, parsedURL(t, "http://x.example.com/admin"), "example.com", nil)
			if assessment != "unknown" {
				t.Error(assessment)
			}
		}()
	}
	wg.Wait()
	if controls.Load() != 3 {
		t.Fatal("calibration not shared", controls.Load())
	}
	classifyDirectory(context.Background(), observer, cache, parsedURL(t, "http://y.example.com/admin"), "example.com", nil)
	if controls.Load() != 6 {
		t.Fatal("origins shared a baseline", controls.Load())
	}
	for _, value := range []string{"http://x.example.com/a/a.php", "http://x.example.com/a/a/", "http://x.example.com/b/a", "https://x.example.com/a", "http://x.example.com:8080/a"} {
		classifyDirectory(context.Background(), observer, cache, parsedURL(t, value), "example.com", nil)
	}
	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()
	if size > 4 {
		t.Fatal("unused cache exceeded bound", size)
	}
	before := controls.Load()
	classifyDirectory(context.Background(), observer, cache, parsedURL(t, "http://x.example.com/admin"), "example.com", nil)
	if controls.Load() != before+3 {
		t.Fatal("evicted context not recalibrated")
	}
}
func TestBaselineControlsMatchRoutingContext(t *testing.T) {
	observer := testObserver(func(r *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(r.URL.Path, "/admin/") || !strings.HasSuffix(r.URL.Path, ".php") {
			t.Error(r.URL.Path)
		}
		return testResponse(404, "Not found", ""), nil
	})
	b := calibrateDirectory(context.Background(), observer, parsedURL(t, "http://x.example.com/admin/example.php"), "example.com", nil)
	if b.requests != 3 || len(b.patterns) == 0 {
		t.Fatal(b)
	}
}
func TestFingerprintSimilarityAndMeaningfulParameters(t *testing.T) {
	u := parsedURL(t, "https://x.example.com/admin")
	var text strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&text, "word%d ", i)
	}
	body := text.String()
	a := makeFingerprint("same", []byte(body+" nonce-a"), "text/html", u)
	b := makeFingerprint("same", []byte(body+" nonce-b"), "text/html", u)
	if !fingerprintsMatch(a, b) {
		t.Fatal("minor dynamic content not matched")
	}
	if fingerprintsMatch(makeFingerprint("same", []byte("short a"), "text/plain", u), makeFingerprint("same", []byte("short b"), "text/plain", u)) {
		t.Fatal("short responses fuzzily matched")
	}
	normalized := normalizeReflection("/login?redirect_to=%2Fadmin&role=owner", u)
	if !strings.Contains(normalized, "role=owner") || strings.Contains(normalized, "%2Fadmin") {
		t.Fatal(normalized)
	}
}
func TestDirectoryWorkerRequestBudgetAndPersistence(t *testing.T) {
	p, _ := newPipelineEnv(t, "passive")
	var active, peak atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		defer active.Add(-1)
		time.Sleep(time.Millisecond)
		if strings.Contains(r.URL.Path, "icevirtue-missing-") {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "Real resource "+r.URL.Path)
	}))
	defer server.Close()
	list := strings.Builder{}
	for i := 0; i < 120; i++ {
		fmt.Fprintf(&list, "ctx%d/page.php\n", i)
	}
	path := writeDirectoryWordlist(t, list.String())
	run := testRunner()
	n, e := run.RunDirectoryFuzzing(p, []models.AliveHost{{URL: server.URL}}, []string{path})
	if e != nil || n != 120 {
		t.Fatal(n, e)
	}
	if peak.Load() > directoryWorkers {
		t.Fatal("request concurrency exceeded", peak.Load())
	}
	var count int64
	testDB.Model(&models.DirectoryFinding{}).Where("assessment='confirmed'").Count(&count)
	if count != 120 {
		t.Fatal(count)
	}
}

func writeDirectoryWordlist(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "words.txt")
	if e := os.WriteFile(p, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
