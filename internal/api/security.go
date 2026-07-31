package api

import (
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

const cookieName = "auth_token"

// authCookie is the only place the session cookie's attributes are written.
//
// Login and logout each built their own literal, and they had already drifted: logout
// omitted SameSite. Harmless as it happened, because SameSite is not part of a cookie's
// identity and the clearing cookie still matched — but it is the shape of bug that
// becomes a vulnerability the next time an attribute is added and only one of the two
// copies learns about it.
//
// maxAge is in seconds, or negative to delete. MaxAge rather than Expires, so the cookie
// does not depend on the client's clock being right.
func (a *API) authCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	}
}

// noStore marks a response as depending on who is asking.
//
// The old handler served the login page and the dashboard from the same URL, with the
// same 200 and no cache headers at all, so a shared cache or the browser's own
// back/forward store could hand the authenticated page to an anonymous visitor.
// Splitting / from /login removes that structurally; this is the backstop.
//
// no-store is the operative directive. no-cache alone permits storage with revalidation,
// which would still land the authenticated dashboard on disk.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// chi's NoCache emits no-cache, no-store, no-transform, must-revalidate, private
		// and max-age=0. Its own doc comment is out of date and omits no-store; the code
		// is what to trust.
		w.Header().Add("Vary", "Cookie")
		middleware.NoCache(next).ServeHTTP(w, r)
	})
}

// pageCSP cannot use a nonce: both pages carry large inline script blocks, and the theme
// resolver in particular has to stay inline and first to avoid a flash of the wrong
// theme. 'unsafe-inline' therefore stays, which costs most of the XSS value — but
// frame-ancestors, base-uri, form-action and connect-src are still worth having and none
// of them requires touching the HTML.
//
// Self-hosting the fonts would let default-src stand alone. That is a follow-up.
const pageCSP = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
	"font-src https://fonts.gstatic.com; " +
	"img-src 'self' data:; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// nosniff and an explicit Content-Type have to arrive together: the pages relied
		// on content sniffing, and nosniff without a declared type makes the browser
		// refuse to render them. renderPage sets the type.
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// The view state now lives in the query string and the pages load fonts from a
		// third party, so this is what keeps a profile UUID out of a Referer header sent
		// to fonts.googleapis.com.
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy", pageCSP)
		next.ServeHTTP(w, r)
	})
}

// requireSameOrigin rejects a state-changing request that the browser itself says came
// from somewhere else.
//
// There was no CSRF defence at all. What protected the app was a coincidence: every
// state-changing endpoint is POST, PUT or DELETE, and SameSite=Lax withholds the cookie
// on a cross-site POST. That is a browser default, not an application control, and
// Chrome's "Lax-allowing-unsafe" carve-out sends the cookie on a cross-site top-level
// POST for two minutes after it is set — long enough for an auto-submitting form with
// enctype="text/plain" and a body crafted to parse as JSON.
//
// Browsers send Origin on every unsafe method and a cross-site page can neither forge
// nor suppress it, so comparing it is a complete defence with no token to issue, store,
// rotate or leak.
func (a *API) requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			// A cross-origin read cannot leak anything: without CORS the attacker's page
			// cannot see the response. Leaving reads unchecked keeps the API scriptable.
			next.ServeHTTP(w, r)
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			// "null" is what a sandboxed iframe, a file:// page and some redirect chains
			// send. It is an origin — an opaque one — not an absent header, so it has to
			// be refused rather than fall through to the no-header case below.
			if origin == "null" || !a.originAllowed(origin, r.Host) {
				a.rejectCrossOrigin(w, r, "Origin", origin)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if ref := r.Header.Get("Referer"); ref != "" {
			u, err := url.Parse(ref)
			if err != nil || !a.originAllowed(u.Scheme+"://"+u.Host, r.Host) {
				a.rejectCrossOrigin(w, r, "Referer", ref)
				return
			}
		}

		// Neither header: this is not a browser. curl, the examples in the README's HTTP
		// API section and any script written against this API all look like that, and
		// none of them can be driven by an attacker's web page. Allowed on purpose.
		next.ServeHTTP(w, r)
	})
}

// originAllowed compares hosts, not full origins.
//
// The scheme is deliberately ignored: behind a TLS-terminating proxy the browser sends
// https:// while this process only ever sees http, and requiring a scheme match would
// reject every write in the most common deployment.
//
// r.Host being client-controlled is not a weakness here. In a cross-site request the
// browser sets Host to the target and Origin to the attacker, so equality fails. An
// attacker who controls both is not using a browser and does not have the victim's
// cookie.
func (a *API) originAllowed(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, host) {
		return true
	}
	for _, trusted := range a.cfg.TrustedOrigins {
		if strings.EqualFold(trusted, origin) || strings.EqualFold(trusted, u.Host) {
			return true
		}
	}
	return false
}

// rejectCrossOrigin refuses the request and names both values.
//
// This is the single most likely deployment failure of the whole change: if a reverse
// proxy rewrites Host while the browser sends the external Origin, every write returns
// 403 and the dashboard looks broken in a way nobody would guess. The log line has to
// say what did not match, and the flag has to be discoverable from it.
func (a *API) rejectCrossOrigin(w http.ResponseWriter, r *http.Request, header, value string) {
	log.Printf("[-] Rejected a %s to %s: %s %q does not match the host %q. "+
		"If this dashboard is behind a reverse proxy, pass --trusted-origin.",
		r.Method, r.URL.Path, header, value, r.Host)
	http.Error(w, "cross-origin request rejected", http.StatusForbidden)
}

// requireJSONBody rejects a body that does not claim to be JSON.
//
// A second, independent control. An HTML form can only send three content types and none
// of them is application/json, so this alone stops the cross-site form post that dresses
// a JSON body up as text/plain, and it does not depend on Origin being present or on the
// browser honouring SameSite.
func requireJSONBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The length check matters: POST /{id}/scan and POST /api/logout legitimately
		// send no body and therefore no Content-Type.
		if r.ContentLength != 0 {
			ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || ct != "application/json" {
				http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// loginLimiter throttles failed logins per client address.
//
// There is one account, bcrypt at cost 10 answers in tens of milliseconds, and this is a
// tool people put on a VPS. Unlimited guessing was the live gap; the constant-time dummy
// hash in handleLogin only hides which half of the credential was wrong.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string]*loginAttempts
	max      int
	lockout  time.Duration
	// maxKeys bounds the map. A map keyed on remote input is itself a resource issue,
	// even though RemoteAddr cannot be spoofed over TCP.
	maxKeys int
}

type loginAttempts struct {
	count int
	last  time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		failures: make(map[string]*loginAttempts),
		max:      5,
		lockout:  15 * time.Minute,
		maxKeys:  10000,
	}
}

// clientKey identifies the caller for rate-limiting purposes.
//
// RemoteAddr only, never X-Forwarded-For. An attacker who can choose the key both
// bypasses the limiter and can lock the real operator out by spoofing their address,
// which is strictly worse than having no limiter at all.
//
// The trade-off to know about: behind a reverse proxy on loopback every request looks
// like 127.0.0.1, so one attacker can lock out the operator. That is stated in the flag
// help rather than hidden here.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// middleware refuses a caller that has failed too often, before the handler runs — so a
// locked-out caller never reaches bcrypt, which protects CPU as well as the password.
func (l *loginLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if retry, blocked := l.blocked(clientKey(r)); blocked {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			// Same shape as the 401 so this is not an oracle for which usernames exist.
			http.Error(w, "Unauthorized", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *loginLimiter) blocked(key string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.evictExpiredLocked()

	entry := l.failures[key]
	if entry == nil || entry.count < l.max {
		return 0, false
	}
	if remaining := l.lockout - time.Since(entry.last); remaining > 0 {
		return remaining, true
	}
	delete(l.failures, key)
	return 0, false
}

func (l *loginLimiter) recordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.evictExpiredLocked()
	if len(l.failures) >= l.maxKeys {
		if _, known := l.failures[key]; !known {
			// Full and this is a new key: drop it rather than grow without bound.
			return
		}
	}

	entry := l.failures[key]
	if entry == nil {
		entry = &loginAttempts{}
		l.failures[key] = entry
	}
	entry.count++
	entry.last = time.Now()
}

// recordSuccess clears the counter, so a correct password ends the lockout for that
// address rather than leaving it to expire.
func (l *loginLimiter) recordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

func (l *loginLimiter) evictExpiredLocked() {
	for key, entry := range l.failures {
		if time.Since(entry.last) > l.lockout {
			delete(l.failures, key)
		}
	}
}

// noListFS serves files and nothing else.
//
// http.FileServer's default behaviour on a directory is to write an index of it, which is
// how GET /static/ came to enumerate the whole web folder. Returning ErrNotExist for a
// directory also suppresses the implicit index.html lookup, so dropping an index.html
// into the asset tree cannot start publishing it either.
type noListFS struct{ fsys http.FileSystem }

func (n noListFS) Open(name string) (http.File, error) {
	f, err := n.fsys.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if info.IsDir() {
		f.Close()
		return nil, fs.ErrNotExist
	}
	return f, nil
}
