package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// These tests exercise the real router, with every middleware in place. The existing
// route() helper calls handlers directly with nothing around them, so it cannot express
// "an unauthenticated request to / is redirected" — that behaviour lives entirely in
// middleware, which is why NewRouter had to be separable from ListenAndServe.

const (
	loginMarker = "LOGIN-MARKER"
	homeMarker  = "DASHBOARD-MARKER"
)

// testAssets stands in for the real web directory. Keeping the routing tests independent
// of the actual 80KB dashboard means an HTML edit cannot break a routing test, and the
// tests assert on markers they placed themselves.
func testAssets() (templates, static fstest.MapFS) {
	return fstest.MapFS{
			"login.html": {Data: []byte(`<!doctype html><title>` + loginMarker + `</title>`)},
			"home.html":  {Data: []byte(`<!doctype html><title>` + homeMarker + `</title>`)},
		}, fstest.MapFS{
			"css/output.css": {Data: []byte(`:root{--x:1}`)},
			"css/theme.css":  {Data: []byte(`:root{--y:2}`)},
			// Something outside css/, to prove the mount point is what limits exposure.
			"secret.txt": {Data: []byte(`should not be served`)},
		}
}

// authOnce loads a signing key once for the whole test binary.
//
// auth.Init is called exactly once on purpose: it is the only way to set the package's
// key, and calling it again with a different path rotates the key, which would silently
// invalidate every token an earlier test in this binary had minted. It cannot use
// t.TempDir either — that is removed when the first test finishes, while the key has to
// outlive all of them.
var authOnce sync.Once

func initAuth(t *testing.T) {
	t.Helper()
	authOnce.Do(func() {
		dir, err := os.MkdirTemp("", "icevirtue-jwt-*")
		if err != nil {
			t.Fatalf("temp dir: %v", err)
		}
		if err := auth.Init(filepath.Join(dir, "jwt.secret")); err != nil {
			t.Fatalf("auth.Init: %v", err)
		}
	})
}

func sessionCookie(t *testing.T, ttl time.Duration) *http.Cookie {
	t.Helper()
	initAuth(t)

	token, err := auth.GenerateTokenWithTTL("netrunner", ttl)
	if err != nil {
		t.Fatalf("GenerateTokenWithTTL: %v", err)
	}
	return &http.Cookie{Name: cookieName, Value: token}
}

func newServer(t *testing.T) http.Handler {
	t.Helper()
	newAPIEnv(t)
	initAuth(t)

	templates, static := testAssets()
	handler, err := NewRouter(Config{Templates: templates, Static: static, SessionTTL: time.Hour}, nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	return handler
}

// do issues a request through the real router. cookie may be nil.
func do(t *testing.T, h http.Handler, method, target string, cookie *http.Cookie, headers ...string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ------------------------------------------------------------------ routing and redirect

func TestUnauthenticatedRootRedirectsToLogin(t *testing.T) {
	rec := do(t, newServer(t), http.MethodGet, "/", nil)

	if rec.Code != http.StatusFound {
		t.Errorf("GET / without a session = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Errorf("Location = %q, want /login", got)
	}
	if strings.Contains(rec.Body.String(), homeMarker) {
		t.Error("the redirect body contains the dashboard")
	}
}

// TestRootRedirectIsNotCacheable guards the status choice. A 301 or 308 is cacheable with
// no explicit freshness, so one anonymous visit would poison / -> /login in that browser
// until its cache was purged.
func TestRootRedirectIsNotCacheable(t *testing.T) {
	rec := do(t, newServer(t), http.MethodGet, "/", nil)

	if rec.Code == http.StatusMovedPermanently || rec.Code == http.StatusPermanentRedirect {
		t.Errorf("the redirect is %d, which is cacheable by default", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want it to contain no-store", cc)
	}
}

func TestAuthenticatedRootServesTheDashboard(t *testing.T) {
	rec := do(t, newServer(t), http.MethodGet, "/", sessionCookie(t, time.Hour))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / with a session = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), homeMarker) {
		t.Error("the dashboard was not served")
	}
	// no-store, an explicit type and Vary all have to be present together: the two
	// variants used to be served from one URL with no cache headers at all, and nosniff
	// without a declared type makes the browser refuse to render the page.
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if v := rec.Header().Get("Vary"); !strings.Contains(v, "Cookie") {
		t.Errorf("Vary = %q, want it to contain Cookie", v)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options is not nosniff")
	}
}

func TestExpiredSessionIsRedirectedNotServed(t *testing.T) {
	rec := do(t, newServer(t), http.MethodGet, "/", sessionCookie(t, -time.Minute))

	if rec.Code != http.StatusFound {
		t.Errorf("GET / with an expired session = %d, want 302", rec.Code)
	}
	if strings.Contains(rec.Body.String(), homeMarker) {
		t.Error("an expired session was served the dashboard")
	}
}

func TestTamperedAndGarbageCookiesAreRedirected(t *testing.T) {
	h := newServer(t)

	valid := sessionCookie(t, time.Hour)
	tampered := &http.Cookie{Name: cookieName, Value: valid.Value[:len(valid.Value)-3] + "AAA"}

	for name, cookie := range map[string]*http.Cookie{
		"tampered signature": tampered,
		"not a token":        {Name: cookieName, Value: "hello"},
		"empty":              {Name: cookieName, Value: ""},
	} {
		rec := do(t, h, http.MethodGet, "/", cookie)
		if rec.Code != http.StatusFound {
			t.Errorf("%s: GET / = %d, want 302", name, rec.Code)
		}
	}
}

func TestLoginPageIsServedWithoutACookie(t *testing.T) {
	rec := do(t, newServer(t), http.MethodGet, "/login", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), loginMarker) {
		t.Error("the login page was not served")
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestAuthenticatedLoginRedirectsToRoot(t *testing.T) {
	rec := do(t, newServer(t), http.MethodGet, "/login", sessionCookie(t, time.Hour))

	if rec.Code != http.StatusFound {
		t.Errorf("GET /login with a session = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Errorf("Location = %q, want /", got)
	}
}

// TestLoginPageDoesNotLoopWithAStaleCookie is the guard against the redirect loop. Both
// sides call the same authenticate(), so a dead cookie has to land on a 200 here — and the
// cookie has to be cleared, or the browser keeps offering it on every request.
func TestLoginPageDoesNotLoopWithAStaleCookie(t *testing.T) {
	rec := do(t, newServer(t), http.MethodGet, "/login", sessionCookie(t, -time.Minute))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login with an expired session = %d, want 200 — anything else is a loop", rec.Code)
	}

	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName && c.Value == "" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the stale cookie was not cleared, so it will be offered again on every request")
	}
}

func TestUnknownPathIs404NotARedirect(t *testing.T) {
	rec := do(t, newServer(t), http.MethodGet, "/nope", nil)

	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /nope = %d, want 404", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("an unknown path redirected to %q; a typo must not bounce", loc)
	}
}

func TestUnknownApiPathReturnsJSON(t *testing.T) {
	rec := do(t, newServer(t), http.MethodGet, "/api/nope", sessionCookie(t, time.Hour))

	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /api/nope = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q; an API miss must not be HTML", ct)
	}
}

func TestNotFoundIsIdenticalAuthenticatedOrNot(t *testing.T) {
	h := newServer(t)

	anon := do(t, h, http.MethodGet, "/nope", nil)
	authed := do(t, h, http.MethodGet, "/nope", sessionCookie(t, time.Hour))

	if anon.Code != authed.Code || anon.Body.String() != authed.Body.String() {
		t.Error("the 404 differs with and without a session, which makes it an existence oracle for routes")
	}
}

func TestHeadRootBehavesLikeGet(t *testing.T) {
	h := newServer(t)

	if rec := do(t, h, http.MethodHead, "/", nil); rec.Code != http.StatusFound {
		t.Errorf("HEAD / without a session = %d, want 302", rec.Code)
	}
	if rec := do(t, h, http.MethodHead, "/", sessionCookie(t, time.Hour)); rec.Code != http.StatusOK {
		t.Errorf("HEAD / with a session = %d, want 200", rec.Code)
	}
}

// ------------------------------------------------------------------------------- static

// TestTemplatesAreNotReachable is the regression test for the exposure this phase closes.
// The old mount served the whole web directory, so GET /static/template.html handed the
// entire authenticated dashboard to anyone and GET /static/ listed the folder.
//
// Path traversal was already refused by http.FileServer, which cleans and rejects "..",
// so those rows are regression guards rather than fixes. The bug being fixed is
// over-broad exposure.
func TestTemplatesAreNotReachable(t *testing.T) {
	h := newServer(t)

	for _, target := range []string{
		"/static/home.html",
		"/static/login.html",
		"/static/secret.txt",
		"/static/css/../secret.txt",
		"/static/css/%2e%2e%2fsecret.txt",
		"/static/",
		"/static/css/",
		"/static/css",
	} {
		rec := do(t, h, http.MethodGet, target, nil)
		if rec.Code == http.StatusOK {
			t.Errorf("GET %s = 200; it must not be served", target)
		}
		body := rec.Body.String()
		if strings.Contains(body, homeMarker) || strings.Contains(body, "should not be served") {
			t.Errorf("GET %s leaked content", target)
		}
		// A directory listing would name the files in it.
		if strings.Contains(body, "output.css") {
			t.Errorf("GET %s produced a directory listing", target)
		}
	}
}

func TestStylesheetsAreServedAndCacheable(t *testing.T) {
	h := newServer(t)

	for _, target := range []string{"/static/css/output.css", "/static/css/theme.css"} {
		rec := do(t, h, http.MethodGet, target, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", target, rec.Code)
		}
		// The stylesheets are the one thing that must stay cacheable, so noStore must not
		// creep onto this group.
		if cc := rec.Header().Get("Cache-Control"); strings.Contains(cc, "no-store") {
			t.Errorf("GET %s is marked no-store; stylesheets should cache", target)
		}
	}
}

// ------------------------------------------------------------------------- auth boundary

// TestEveryRouteIsEitherPublicOrGuarded walks the real router.
//
// This is the test that makes "forgot the auth middleware" unmergeable, and the bug it
// guards against is exactly how GET / and /static/* came to serve the authenticated
// dashboard to anyone: a route registered outside the group. A hand-written list of
// protected endpoints cannot catch a route nobody remembered to add to the list; walking
// the router can.
func TestEveryRouteIsEitherPublicOrGuarded(t *testing.T) {
	public := map[string]bool{
		"GET /login":         true,
		"HEAD /login":        true,
		"POST /api/login":    true,
		"POST /api/logout":   true,
		"GET /static/css/*":  true,
		"HEAD /static/css/*": true,
	}

	h := newServer(t)
	routes, ok := h.(chi.Routes)
	if !ok {
		t.Fatal("the router does not expose chi.Routes, so it cannot be walked")
	}

	err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if public[method+" "+route] {
			return nil
		}

		target := strings.ReplaceAll(route, "{id}", uuid.NewString())
		target = strings.TrimSuffix(target, "/*")
		if target == "" {
			target = "/"
		}

		rec := do(t, h, method, target, nil)
		switch rec.Code {
		case http.StatusUnauthorized, http.StatusFound:
			// Guarded: the API answers 401, the HTML routes redirect.
		default:
			t.Errorf("%s %s answered %d without a session; it is neither on the public list nor guarded",
				method, route, rec.Code)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
}

func TestApiReturns401NotARedirect(t *testing.T) {
	rec := do(t, newServer(t), http.MethodGet, "/api/profiles", nil)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/profiles without a session = %d, want 401", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("the API redirected to %q; fetch needs a status, not an HTML login page", loc)
	}
}

// ---------------------------------------------------------------------------------- CSRF

func TestCrossOriginWriteIsRejected(t *testing.T) {
	h := newServer(t)
	cookie := sessionCookie(t, time.Hour)

	rec := do(t, h, http.MethodPost, "/api/profiles", cookie,
		"Origin", "http://evil.example", "Content-Type", "application/json")
	if rec.Code != http.StatusForbidden {
		t.Errorf("a cross-origin POST = %d, want 403", rec.Code)
	}
}

func TestNullOriginIsRejected(t *testing.T) {
	rec := do(t, newServer(t), http.MethodPost, "/api/profiles", sessionCookie(t, time.Hour),
		"Origin", "null", "Content-Type", "application/json")

	// "null" is an origin — an opaque one — not an absent header, so it must not fall
	// through to the "not a browser" case.
	if rec.Code != http.StatusForbidden {
		t.Errorf("Origin: null = %d, want 403", rec.Code)
	}
}

func TestSameOriginWriteIsAccepted(t *testing.T) {
	h := newServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/profiles",
		strings.NewReader(`{"domain":"same-origin.example.net","schedule":"every day at 03:00"}`))
	req.AddCookie(sessionCookie(t, time.Hour))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+req.Host)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("a same-origin POST = %d, want 201: %s", rec.Code, rec.Body.String())
	}
}

// TestWriteWithNoOriginOrRefererIsAccepted documents a deliberate trade-off: a request
// with neither header is not a browser, so it cannot be driven by an attacker's page. The
// README's curl examples look exactly like this.
func TestWriteWithNoOriginOrRefererIsAccepted(t *testing.T) {
	h := newServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/profiles",
		strings.NewReader(`{"domain":"curl.example.com","schedule":"every day at 03:00"}`))
	req.AddCookie(sessionCookie(t, time.Hour))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("a header-less POST = %d, want 201: %s", rec.Code, rec.Body.String())
	}
}

func TestReadIsNotOriginChecked(t *testing.T) {
	rec := do(t, newServer(t), http.MethodGet, "/api/profiles", sessionCookie(t, time.Hour),
		"Origin", "http://evil.example")

	// A cross-origin read cannot leak anything without CORS, and leaving reads unchecked
	// keeps the API scriptable.
	if rec.Code != http.StatusOK {
		t.Errorf("a cross-origin GET = %d, want 200", rec.Code)
	}
}

func TestTrustedOriginIsAccepted(t *testing.T) {
	newAPIEnv(t)
	initAuth(t)

	templates, static := testAssets()
	h, err := NewRouter(Config{
		Templates: templates, Static: static, SessionTTL: time.Hour,
		TrustedOrigins: []string{"https://recon.example.com"},
	}, nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/profiles",
		strings.NewReader(`{"domain":"proxied.example.com","schedule":"every day at 03:00"}`))
	req.AddCookie(sessionCookie(t, time.Hour))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://recon.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("a trusted-origin POST = %d, want 201: %s", rec.Code, rec.Body.String())
	}
}

// TestNonJSONBodyIsRejected covers the second, independent CSRF control. An HTML form can
// only send three content types and none of them is application/json, so this alone stops
// the cross-site form post that dresses a JSON body up as text/plain.
func TestNonJSONBodyIsRejected(t *testing.T) {
	h := newServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/profiles",
		strings.NewReader(`{"domain":"example.com","schedule":"every day at 03:00"}`))
	req.AddCookie(sessionCookie(t, time.Hour))
	req.Header.Set("Content-Type", "text/plain")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("a text/plain body = %d, want 415", rec.Code)
	}
}

// TestBodylessPostNeedsNoContentType guards against the JSON check breaking the endpoints
// that legitimately send nothing.
func TestBodylessPostNeedsNoContentType(t *testing.T) {
	h := newServer(t)

	if rec := do(t, h, http.MethodPost, "/api/logout", nil); rec.Code == http.StatusUnsupportedMediaType {
		t.Error("POST /api/logout with no body was rejected as non-JSON")
	}

	rec := do(t, h, http.MethodPost, "/api/profiles/"+uuid.NewString()+"/scan", sessionCookie(t, time.Hour))
	if rec.Code == http.StatusUnsupportedMediaType {
		t.Error("POST /scan with no body was rejected as non-JSON")
	}
}

// -------------------------------------------------------------------------------- cookies

func TestSessionCookieIsHardened(t *testing.T) {
	newAPIEnv(t)
	initAuth(t)
	seedUser(t, "netrunner", "correct-horse-battery")

	for _, secure := range []bool{false, true} {
		templates, static := testAssets()
		h, err := NewRouter(Config{
			Templates: templates, Static: static, SessionTTL: time.Hour, SecureCookies: secure,
		}, nil)
		if err != nil {
			t.Fatalf("NewRouter: %v", err)
		}

		rec := postJSON(t, h, "/api/login", `{"username":"netrunner","password":"correct-horse-battery"}`, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("login = %d: %s", rec.Code, rec.Body.String())
		}

		cookie := findCookie(rec, cookieName)
		if cookie == nil {
			t.Fatal("login set no session cookie")
		}
		if !cookie.HttpOnly {
			t.Error("the session cookie is not HttpOnly")
		}
		if cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
		}
		if cookie.Path != "/" {
			t.Errorf("Path = %q, want /", cookie.Path)
		}
		if cookie.Secure != secure {
			t.Errorf("SecureCookies=%v produced Secure=%v", secure, cookie.Secure)
		}
	}
}

// TestLogoutCookieMatchesLoginCookie is the test that stops the two http.SetCookie
// literals from diverging again. They already had: logout omitted SameSite.
func TestLogoutCookieMatchesLoginCookie(t *testing.T) {
	newAPIEnv(t)
	initAuth(t)
	seedUser(t, "netrunner", "correct-horse-battery")
	h := newServerWithUsers(t)

	login := findCookie(postJSON(t, h, "/api/login",
		`{"username":"netrunner","password":"correct-horse-battery"}`, nil), cookieName)
	logout := findCookie(do(t, h, http.MethodPost, "/api/logout", nil), cookieName)

	if login == nil || logout == nil {
		t.Fatal("one of the two responses set no cookie")
	}
	if login.Name != logout.Name || login.Path != logout.Path ||
		login.HttpOnly != logout.HttpOnly || login.Secure != logout.Secure ||
		login.SameSite != logout.SameSite {
		t.Errorf("the login and logout cookies differ:\n  login  %+v\n  logout %+v", login, logout)
	}
	if logout.Value != "" || logout.MaxAge >= 0 {
		t.Errorf("the logout cookie does not clear the session: value=%q maxAge=%d", logout.Value, logout.MaxAge)
	}
}

// ---------------------------------------------------------------------------------- login

func TestLoginRejectsBadCredentialsIndistinguishably(t *testing.T) {
	newAPIEnv(t)
	initAuth(t)
	seedUser(t, "netrunner", "correct-horse-battery")
	h := newServerWithUsers(t)

	wrongPassword := postJSON(t, h, "/api/login", `{"username":"netrunner","password":"nope"}`, nil)
	unknownUser := postJSON(t, h, "/api/login", `{"username":"nobody","password":"nope"}`, nil)

	if wrongPassword.Code != http.StatusUnauthorized || unknownUser.Code != http.StatusUnauthorized {
		t.Errorf("statuses = %d and %d, want 401 for both", wrongPassword.Code, unknownUser.Code)
	}
	if wrongPassword.Body.String() != unknownUser.Body.String() {
		t.Error("the two failures differ, which reveals whether the username exists")
	}
}

func TestMalformedLoginBodyIs400(t *testing.T) {
	h := newServer(t)

	rec := postJSON(t, h, "/api/login", `{not json`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a malformed login body = %d, want 400: a parse failure is not an auth failure", rec.Code)
	}
}

// TestLoginIsRateLimited covers the brute-force gap. There was no limit of any kind, and
// bcrypt at cost 10 answers in tens of milliseconds.
func TestLoginIsRateLimited(t *testing.T) {
	newAPIEnv(t)
	initAuth(t)
	seedUser(t, "netrunner", "correct-horse-battery")
	h := newServerWithUsers(t)

	const attempts = 6
	var last *httptest.ResponseRecorder
	for range attempts {
		last = postJSON(t, h, "/api/login", `{"username":"netrunner","password":"wrong"}`, nil)
	}

	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures the status is %d, want 429", attempts, last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Error("the 429 carries no Retry-After")
	}

	// A correct password during the lockout is still refused: the limiter runs before the
	// handler, so a locked-out caller never reaches bcrypt.
	correct := postJSON(t, h, "/api/login", `{"username":"netrunner","password":"correct-horse-battery"}`, nil)
	if correct.Code != http.StatusTooManyRequests {
		t.Errorf("a correct password during the lockout = %d, want 429", correct.Code)
	}

	// A different address is unaffected, so one attacker cannot lock everyone out.
	req := httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"username":"netrunner","password":"correct-horse-battery"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:44444"
	other := httptest.NewRecorder()
	h.ServeHTTP(other, req)
	if other.Code != http.StatusOK {
		t.Errorf("a different client = %d, want 200: the limiter must be per-address", other.Code)
	}
}

// ------------------------------------------------------------------------------- helpers

func seedUser(t *testing.T, username, password string) {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	if err := database.DB.Create(&models.User{Username: username, PasswordHash: string(hash)}).Error; err != nil {
		t.Fatalf("seeding user %s: %v", username, err)
	}
}

// newServerWithUsers builds a router without resetting the database, so a caller can seed
// users first.
func newServerWithUsers(t *testing.T) http.Handler {
	t.Helper()

	templates, static := testAssets()
	h, err := NewRouter(Config{Templates: templates, Static: static, SessionTTL: time.Hour}, nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	return h
}

func postJSON(t *testing.T, h http.Handler, target, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
