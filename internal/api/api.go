package api

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/engine"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/scheduler"
)

var globalScheduler *scheduler.Scheduler

func StartServer(port int, s *scheduler.Scheduler) {
	globalScheduler = s
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Post("/api/login", handleLogin)
	r.Post("/api/logout", handleLogout)
	r.Get("/", handleDashboard)
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("web"))))

	r.Route("/api/profiles", func(r chi.Router) {
		r.Use(authMiddleware)
		r.Get("/", getProfiles)
		// Registered before the /{id} subrouter so "index" is not read as a profile id.
		r.Get("/index", getProfileIndex)
		r.Post("/", createProfile)
		r.Route("/{id}", func(r chi.Router) {
			r.Delete("/", deleteProfile)
			r.Put("/schedule", editProfileSchedule)
			r.Post("/scan", forceScanProfile)
			r.Get("/subdomains", getProfileSubdomains)
			r.Get("/secrets", getProfileSecrets)
			r.Get("/hosts", getProfileHosts)
			r.Get("/vulnerabilities", getProfileVulnerabilities)
			r.Get("/directories", getProfileDirectories)
		})
	})

	r.Route("/api/events", func(r chi.Router) {
		r.Use(authMiddleware)
		r.Get("/", handleEvents)
	})

	addr := fmt.Sprintf(":%d", port)
	log.Printf("[+] Web dashboard listening on %s", addr)
	err := http.ListenAndServe(addr, r)
	if err != nil {
		log.Fatalf("[-] Web server failed: %v", err)
	}
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	isAuthenticated := false
	cookie, err := r.Cookie("auth_token")
	if err == nil {
		_, err = auth.ValidateToken(cookie.Value)
		if err == nil {
			isAuthenticated = true
		}
	}

	var tmplPath string
	if isAuthenticated {
		tmplPath = filepath.Join("web", "template.html")
	} else {
		tmplPath = filepath.Join("web", "login.html")
	}

	tmplBytes, err := os.ReadFile(tmplPath)
	if err != nil {
		http.Error(w, "Failed to read template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.New("dashboard").Parse(string(tmplBytes))
	if err != nil {
		http.Error(w, "Failed to parse template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Nothing is injected into either page: both templates contain zero actions, and
	// the client reads its own state from the query string. The unbounded
	// Find(&profiles) that used to run here fed a variable neither template ever
	// referenced, on a route reachable without authentication.
	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Failed to execute template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		_, err = auth.ValidateToken(cookie.Value)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	broker := events.GetBroker()
	clientChan := broker.Subscribe()
	defer broker.Unsubscribe(clientChan)

	// Keep alive immediately
	fmt.Fprintf(w, ": keep-alive\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return // Client disconnected
		case e := <-clientChan:
			msg, err := json.Marshal(e)
			if err == nil {
				fmt.Fprintf(w, "data: %s\n\n", msg)
				flusher.Flush()
			}
		}
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user models.User
	result := database.DB.Where("username = ?", req.Username).First(&user)

	dummyHash := "$2a$10$w1Dq7OaHxzB5vI/.wQ8/e.cIhA1JvE6cMwI8V/.1S/8gP.G/N./O2"

	hashToCompare := dummyHash
	if result.Error == nil {
		hashToCompare = user.PasswordHash
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashToCompare), []byte(req.Password))

	if result.Error != nil || err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString, err := auth.GenerateToken(user.Username)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    tokenString,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	respondJSON(w, http.StatusOK, map[string]string{"message": "success"})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})
	respondJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

var profileSorts = map[string]string{
	"domain-asc":  "profiles.domain ASC, profiles.id ASC",
	"domain-desc": "profiles.domain DESC, profiles.id DESC",
	"scan-desc":   "profiles.last_scan DESC, profiles.domain ASC",
	"scan-asc":    "profiles.last_scan ASC, profiles.domain ASC",
}

// getProfiles serves the targets table, paginated.
func getProfiles(w http.ResponseWriter, r *http.Request) {
	q := parseListQuery(r, defaultPageProfiles, profileSorts, "domain-asc")
	listPage[models.Profile](w, q, &models.Profile{}, "",
		func(db *gorm.DB) *gorm.DB { return db }, profileSorts[q.Sort])
}

// profileOption is the two-column shape the profile picker needs.
type profileOption struct {
	ID     uuid.UUID `json:"id"`
	Domain string    `json:"domain"`
}

// getProfileIndex lists every profile as an id and a name, unpaginated.
//
// This exists because the dashboard fills both the targets table and the profile
// picker from one request. Paginating that single endpoint at 25 would silently
// truncate the dropdown, leaving the 26th target unreachable with nothing on screen to
// explain why — so the picker gets its own endpoint instead.
//
// It is a deliberate exception to "everything is paginated", and a narrow one: two
// columns for even a few thousand profiles is an index-only scan and a response
// measured in tens of kilobytes, while the finding tables it sits next to are the ones
// that reach tens of thousands of rows.
func getProfileIndex(w http.ResponseWriter, r *http.Request) {
	var options []profileOption
	if err := database.DB.Model(&models.Profile{}).
		Select("profiles.id, profiles.domain").
		Order("profiles.domain ASC").
		Scan(&options).Error; err != nil {
		log.Printf("[-] Listing the profile index: %v", err)
		http.Error(w, "failed to list profiles", http.StatusInternalServerError)
		return
	}

	if options == nil {
		options = []profileOption{}
	}
	respondJSON(w, http.StatusOK, options)
}

func createProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain   string `json:"domain"`
		Schedule string `json:"schedule"`
		Mode     string `json:"mode"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Domain == "" || req.Schedule == "" {
		http.Error(w, "domain and schedule are required", http.StatusBadRequest)
		return
	}

	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !domainRegex.MatchString(req.Domain) {
		http.Error(w, "Invalid domain format", http.StatusBadRequest)
		return
	}

	if req.Mode == "" {
		req.Mode = "full"
	}

	var existingProfile models.Profile
	if err := database.DB.Unscoped().Where("domain = ?", req.Domain).First(&existingProfile).Error; err == nil {
		http.Error(w, "profile already exists", http.StatusConflict)
		return
	}

	profile := models.Profile{
		Domain:   req.Domain,
		Schedule: req.Schedule,
		Mode:     req.Mode,
		Enabled:  true,
	}

	if err := database.DB.Create(&profile).Error; err != nil {
		http.Error(w, "failed to create profile: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if globalScheduler != nil {
		globalScheduler.Sync()
	}

	respondJSON(w, http.StatusCreated, profile)
}

func deleteProfile(w http.ResponseWriter, r *http.Request) {
	idParam := chi.URLParam(r, "id")
	if idParam == "" {
		http.Error(w, "missing profile id", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(idParam)
	if err != nil {
		http.Error(w, "invalid UUID format", http.StatusBadRequest)
		return
	}

	var profile models.Profile
	if err := database.DB.First(&profile, id).Error; err != nil {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}

	// Delete related child records first to ensure we don't leave orphaned data.
	// Every finding table a stage can write to has to be listed here; missing one
	// leaves rows behind that no profile owns and that nothing will ever read.
	database.DB.Where("profile_id = ?", id).Delete(&models.Subdomain{})
	database.DB.Where("profile_id = ?", id).Delete(&models.AliveHost{})
	database.DB.Where("profile_id = ?", id).Delete(&models.Vulnerability{})
	database.DB.Where("profile_id = ?", id).Delete(&models.SecretFinding{})
	database.DB.Where("profile_id = ?", id).Delete(&models.DirectoryFinding{})

	// Hard delete the profile itself
	if err := database.DB.Unscoped().Delete(&profile).Error; err != nil {
		http.Error(w, "failed to delete profile: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if globalScheduler != nil {
		globalScheduler.Sync()
	}

	w.WriteHeader(http.StatusNoContent)
}

func editProfileSchedule(w http.ResponseWriter, r *http.Request) {
	idParam := chi.URLParam(r, "id")
	if idParam == "" {
		http.Error(w, "missing profile id", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(idParam)
	if err != nil {
		http.Error(w, "invalid UUID format", http.StatusBadRequest)
		return
	}

	var req struct {
		Schedule string `json:"schedule"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Schedule == "" {
		http.Error(w, "schedule is required", http.StatusBadRequest)
		return
	}

	var profile models.Profile
	if err := database.DB.First(&profile, id).Error; err != nil {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}

	if err := database.DB.Model(&profile).Update("schedule", req.Schedule).Error; err != nil {
		http.Error(w, "failed to update schedule: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if globalScheduler != nil {
		globalScheduler.Sync()
	}

	respondJSON(w, http.StatusOK, map[string]string{"schedule": profile.Schedule})
}

func forceScanProfile(w http.ResponseWriter, r *http.Request) {
	idParam := chi.URLParam(r, "id")
	if idParam == "" {
		http.Error(w, "missing profile id", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(idParam)
	if err != nil {
		http.Error(w, "invalid UUID format", http.StatusBadRequest)
		return
	}

	var profile models.Profile
	if err := database.DB.First(&profile, id).Error; err != nil {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}

	// Optimistic pre-check so the obvious case (double-clicking Initiate) gets a
	// 409 instead of a 202 that quietly does nothing. It is NOT the guard against
	// concurrent runs: OrchestrateScan claims the lock atomically and is the only
	// authority on whether a run actually starts.
	if profile.IsScanning {
		http.Error(w, "profile is already scanning", http.StatusConflict)
		return
	}

	go engine.OrchestrateScan(&profile)

	respondJSON(w, http.StatusAccepted, map[string]string{"message": "scan started in background"})
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
