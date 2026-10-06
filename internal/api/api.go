package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"

	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/access"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/accounts"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/jobs"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/notifications"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/wordlists"
	"gorm.io/gorm"
)

// Config is everything the server needs from main, so this package reads no flags and
// touches no filesystem at import time — which is what lets a test build a real router
// with fabricated assets.
type Config struct {
	DB        *gorm.DB
	Signer    *auth.Signer
	Shutdown  <-chan struct{}
	Wordlists *wordlists.Store
	// Templates holds login.html and home.html. It is deliberately NOT the tree served
	// under /static: the previous layout served the whole web directory, so
	// GET /static/template.html handed the entire authenticated dashboard to anyone.
	Templates fs.FS
	// Static is served under /static, and nothing outside it is addressable.
	Static fs.FS
	// ReloadTemplates re-reads the pages on every request. Development only.
	ReloadTemplates bool
	SecureCookies   bool
	TrustedOrigins  []string
	SessionTTL      time.Duration
}

// API carries what the handlers need.
//
// This replaces a package-level globalScheduler, which could not be set per test and
// would race under any parallel one.
type API struct {
	inbox    *notifications.Service
	queries  *queryService
	sessions *accounts.Sessions
	uploads  chan struct{}
	cfg      Config
	db       *gorm.DB
	signer   *auth.Signer
	queue    *jobs.Queue
	stream   *events.Stream
	pages    *pageStore
	logins   *loginLimiter
}

// NewRouter builds the complete handler, including every middleware.
//
// It is exported and separate from StartServer so a test can exercise the real routing —
// the redirect, the cache headers, the auth boundary — rather than calling handlers
// directly with nothing around them. StartServer used to construct the router and call
// ListenAndServe in one function, so there was no way to get at the handler.
func NewRouter(cfg Config) (http.Handler, error) {
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = auth.DefaultSessionTTL
	}

	if cfg.SessionTTL < time.Second || cfg.SessionTTL > auth.MaxSessionTTL {
		return nil, fmt.Errorf("session TTL must be between one second and seven days")
	}

	pages, err := newPageStore(cfg)
	if err != nil {
		// Fail startup rather than a user's first page load: a broken template used to
		// surface as a 500 with the template error in the body.
		return nil, err
	}

	cssFS, err := fs.Sub(cfg.Static, "css")
	if err != nil {
		return nil, fmt.Errorf("static assets have no css directory: %w", err)
	}

	jsFS, err := fs.Sub(cfg.Static, "js")
	if err != nil {
		return nil, fmt.Errorf("static assets have no js directory: %w", err)
	}
	a := &API{inbox: &notifications.Service{DB: cfg.DB}, queries: &queryService{db: cfg.DB}, sessions: &accounts.Sessions{DB: cfg.DB, Signer: cfg.Signer}, db: cfg.DB, signer: cfg.Signer, queue: &jobs.Queue{DB: cfg.DB}, stream: &events.Stream{DB: cfg.DB}, cfg: cfg, pages: pages, logins: newLoginLimiter(), uploads: make(chan struct{}, 1)}

	r := chi.NewRouter()

	// All root middleware must be registered before any route: chi panics on a Use after
	// a route has been added to the same mux.
	r.Use(middleware.RequestID)
	r.Use(requestLog)
	r.Use(middleware.Recoverer)
	r.Use(middleware.GetHead)
	r.Use(securityHeaders)
	// No CORS middleware. AllowedOrigins "*" together with AllowCredentials true was
	// inert — browsers refuse a credentialed response whose ACAO is "*" — but it was
	// self-contradictory, it would become account takeover the day anyone switched to a
	// reflected origin, and it advertised an X-CSRF-Token header that was never issued or
	// checked. See Config.TrustedOrigins for the cross-origin case that does exist.

	// Public: the pre-auth page.
	r.Group(func(r chi.Router) {
		r.Use(noStore)
		r.Get("/login", a.handleLoginPage)
	})

	// Public: the auth endpoints.
	r.Group(func(r chi.Router) {
		r.Use(noStore)
		r.Use(a.requireSameOrigin)
		r.Use(requireJSONBody)
		r.Use(middleware.RequestSize(64 << 10))
		r.With(a.logins.middleware).Post("/api/login", a.handleLogin)
		r.Post("/api/logout", a.handleLogout)
	})

	// Public asset directories are explicitly limited to css and js; directory listings are denied.
	r.Get("/static/css/*", http.StripPrefix("/static/css/",
		http.FileServer(noListFS{http.FS(cssFS)})).ServeHTTP)
	r.Get("/static/js/*", http.StripPrefix("/static/js/", http.FileServer(noListFS{http.FS(jsFS)})).ServeHTTP)

	// Authenticated HTML. Redirects rather than 401s.
	r.Group(func(r chi.Router) {
		r.Use(noStore)
		r.Use(a.requirePageAuth)
		r.Get("/", a.handleHome)
		a.settingsRoutes(r)
	})

	// Authenticated API. 401s rather than redirects, so fetch sees a status instead of an
	// HTML login page.
	r.Group(func(r chi.Router) {
		r.Use(noStore)
		r.Use(a.requireAPIAuth)
		r.Use(requireWritePermission)
		r.Use(a.requireSameOrigin)
		r.Use(requireJSONBody)
		r.Use(middleware.RequestSize(1 << 20))

		r.Route("/api/profiles", func(r chi.Router) {
			r.Get("/", a.getProfiles)
			// Before the /{id} subrouter, so "index" is not read as a profile id.
			r.Get("/index", a.getProfileIndex)
			r.Post("/", a.createProfile)
			r.Route("/{id}", func(r chi.Router) {
				r.Delete("/", a.deleteProfile)
				r.Put("/schedule", a.editProfileSchedule)
				r.Post("/scan", a.forceScanProfile)
				r.Get("/overview", a.getProfileOverview)
				r.Get("/subdomains", a.getProfileSubdomains)
				r.Get("/secrets", a.getProfileSecrets)
				r.Get("/hosts", a.getProfileHosts)
				r.Get("/wafs", a.getProfileWAFs)
				r.Get("/vulnerabilities/severity-summary", a.getVulnerabilitySeveritySummary)
				r.Get("/vulnerabilities", a.getProfileVulnerabilities)
				r.Get("/directories", a.getProfileDirectories)
				r.Get("/redirects", a.getProfileRedirects)
				r.Get("/redirects/summary", a.getRedirectSummary)
			})
		})

		r.Route("/api/notifications", func(r chi.Router) {
			r.Get("/", a.getNotifications)
			r.Delete("/", a.deleteAllNotifications)
			r.Post("/read", a.markAllNotificationsRead)
			r.Route("/{id}", func(r chi.Router) {
				r.Post("/read", a.markNotificationRead)
				r.Delete("/", a.deleteNotification)
			})
		})

		r.Get("/api/events", a.handleEvents)
		r.Get("/api/profiles/{id}/runs", a.listRuns)
		r.Get("/api/runs/{runID}", a.getRun)
		r.With(requirePermission(access.ReadLogs)).Get("/api/admin/workers", a.workerStatus)
	})

	a.configurationRoutes(r)
	r.NotFound(notFound)
	r.MethodNotAllowed(methodNotAllowed)

	return r, nil
}

// ---------------------------------------------------------------------- authentication

// claimsKey is unexported so nothing outside this package can put a value under it.
type claimsKey struct{}

// UserFromContext returns the authenticated user, if the request went through a guard.
func UserFromContext(ctx interface{ Value(any) any }) (*auth.Claims, bool) {
	claims, ok := ctx.Value(claimsKey{}).(*auth.Claims)
	return claims, ok
}

// authenticate is the single decision point for "is this request authenticated".
//
// It used to exist twice, in two different styles: an inline block in the page handler
// and a middleware. Both guards call this one now, which is what makes a redirect loop
// between / and /login structurally impossible — the two sides cannot disagree.
//
// It returns the claims rather than discarding them, so a handler can finally see who is
// asking. The SSE handler needs the expiry.
func (a *API) authenticate(r *http.Request) (*auth.Claims, *models.User, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, nil, err
	}
	c, err := a.signer.ValidateToken(cookie.Value)
	if err != nil {
		return nil, nil, err
	}
	u, err := a.sessionUser(c)
	return c, u, err
}

// requirePageAuth guards HTML routes. An unauthenticated browser is sent to the login
// page rather than shown a 401 body, which is what makes the split between / and /login
// enforceable on the server instead of decided inside one handler.
func (a *API) requirePageAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, user, err := a.authenticate(r)
		if err != nil {
			// 302, deliberately not 301 or 308. A permanent redirect is cacheable with no
			// explicit freshness, so one anonymous visit would poison / -> /login in that
			// browser until its cache was purged. noStore has already run, so this
			// response is not stored either.
			http.SetCookie(w, a.authCookie("", -1))
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r.WithContext(authenticatedContext(r, claims, user)))
	})
}

// requireAPIAuth guards the JSON API. It answers 401 rather than redirecting, because a
// fetch that follows a redirect to an HTML page cannot tell what went wrong.
func (a *API) requireAPIAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, user, err := a.authenticate(r)
		if err != nil {
			http.SetCookie(w, a.authCookie("", -1))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(authenticatedContext(r, claims, user)))
	})
}

// ------------------------------------------------------------------------- page serving

// pageStore holds the parsed pages.
//
// They used to be read from disk and re-parsed on every single request, with the path
// resolved against whatever the working directory happened to be.
type pageStore struct {
	current atomic.Pointer[pageSet]
	fsys    fs.FS
	reload  bool
}

type pageSet struct {
	login    *template.Template
	home     *template.Template
	settings map[string]*template.Template
}

func newPageStore(cfg Config) (*pageStore, error) {
	store := &pageStore{fsys: cfg.Templates, reload: cfg.ReloadTemplates}
	pages, err := parsePages(cfg.Templates)
	if err != nil {
		return nil, err
	}
	store.current.Store(pages)
	return store, nil
}

func parsePages(fsys fs.FS) (*pageSet, error) {
	// html/template escapes all server-provided values in their output context.
	login, err := template.New("login.html").ParseFS(fsys, "login.html")
	if err != nil {
		return nil, fmt.Errorf("parsing the login page: %w", err)
	}
	home, err := template.New("home.html").ParseFS(fsys, "home.html")
	if err != nil {
		return nil, fmt.Errorf("parsing the dashboard page: %w", err)
	}
	settings, err := parseSettingsPages(fsys)
	if err != nil {
		return nil, err
	}
	return &pageSet{login: login, home: home, settings: settings}, nil
}

// get returns the pages, re-parsing them first in development.
//
// The whole set is swapped as one pointer rather than re-parsed in place: a
// template.Template is safe for concurrent Execute only once parsing has finished, so
// re-parsing one that another request may be executing is a data race.
func (p *pageStore) get() (*pageSet, error) {
	if !p.reload {
		return p.current.Load(), nil
	}
	fresh, err := parsePages(p.fsys)
	if err != nil {
		return nil, err
	}
	p.current.Store(fresh)
	return fresh, nil
}

func (a *API) handleHome(w http.ResponseWriter, r *http.Request) {
	pages, err := a.pages.get()
	if err != nil {
		log.Printf("[-] Reloading templates: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	a.renderData(w, pages.home, homeData(currentUser(r)))
}

func (a *API) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, err := a.authenticate(r); err == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// A cookie that is present but not valid — expired, tampered with, signed with a
	// rotated key — must not keep being offered on every subsequent request. Clearing it
	// here is also what makes a redirect loop impossible: this branch serves a 200, so a
	// browser holding a dead cookie lands on the login page instead of bouncing.
	if _, err := r.Cookie(cookieName); err == nil {
		http.SetCookie(w, a.authCookie("", -1))
	}

	pages, err := a.pages.get()
	if err != nil {
		log.Printf("[-] Reloading templates: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	notice := ""
	switch r.URL.Query().Get("reason") {
	case "account-updated":
		notice = "Your account was updated. Sign in again with your current credentials."
	case "session-ended":
		notice = "Your session ended or your account changed. Sign in again to continue."
	}
	a.renderData(w, pages.login, pageData{Notice: notice})
}

// renderData buffers the page before writing it.
//
// Executing straight into the ResponseWriter meant a failure halfway through had already
// sent a 200 and a partial body, so the http.Error that followed appended its message
// into the middle of the HTML. Buffering makes the response all-or-nothing.
//
// html/template escapes account fields and log text in the server-rendered pages.
// Privileged account forms are loaded only after authentication and authorization.
func (a *API) renderData(w http.ResponseWriter, tmpl *template.Template, data interface{}) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		// The caller gets a status and nothing else. The old handler put err.Error() in
		// the body, which told an unauthenticated visitor the absolute path of the
		// template directory.
		log.Printf("[-] Rendering %s: %v", tmpl.Name(), err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Explicit, because securityHeaders sets nosniff and a browser will refuse to render
	// a document whose type it is not allowed to guess.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
}

// -------------------------------------------------------------------------- not found

// notFound answers in the shape the caller expects.
//
// An /api/* miss must not be HTML: the dashboard parses JSON, so a stray HTML body turns
// a typo into an unreadable parse error. An unknown path is a 404 and never a redirect to
// /login — redirecting would turn every typo into a bounce and hand an API client an HTML
// page with a 302 instead of a 404.
func notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	http.Error(w, "404 page not found", http.StatusNotFound)
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// chi's default writes a 405 with no Allow header at all.
	if allowed := chi.RouteContext(r.Context()); allowed != nil {
		w.Header().Set("Allow", strings.Join(allowedMethods(r), ", "))
	}
	http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
}

func allowedMethods(r *http.Request) []string {
	// chi does not expose the matched methods, so report the ones this app ever uses for
	// a resource path. It is advisory; the status is what matters.
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return []string{"GET", "POST", "PUT", "DELETE"}
	}
	return []string{"GET", "HEAD"}
}

// ------------------------------------------------------------------------------- events

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// DirFS is a small helper so main can build a Config from a directory without importing
// io/fs itself.
func DirFS(dir string) fs.FS { return os.DirFS(dir) }
