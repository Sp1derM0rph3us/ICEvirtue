package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/jobs"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/profiles"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/scheduler"
)

// The one rule that governs every transaction in this file:
//
//	Inside Transaction(func(tx *gorm.DB)), use only tx.
//
// database.go sets SetMaxOpenConns(1), so a call through the package-level a.db
// inside a transaction callback waits for a connection from a pool of exactly one that
// the transaction itself is holding — and database/sql waits with no timeout. That is a
// permanent hang, not a slow query, and busy_timeout does not help because the block is
// in Go. The same applies to Sync(), which reads the database and therefore stays outside.

// domainPattern is compiled once. It used to be compiled on every request.
var domainPattern = regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

var profileSorts = map[string]string{
	"domain-asc":  "profiles.domain ASC, profiles.id ASC",
	"domain-desc": "profiles.domain DESC, profiles.id DESC",
	"scan-desc":   "julianday(profiles.last_scan) DESC, profiles.domain ASC",
	"scan-asc":    "julianday(profiles.last_scan) ASC, profiles.domain ASC",
}

// a.getProfiles serves the targets table, paginated.
func (a *API) getProfiles(w http.ResponseWriter, r *http.Request) {
	q := parseListQuery(r, defaultPageProfiles, profileSorts, "domain-asc")
	listPage[models.Profile](a.queries, w, q, &models.Profile{}, "",
		func(db *gorm.DB) *gorm.DB { return db }, profileSorts[q.Sort])
}

// profileOption is the two-column shape the profile picker needs.
type profileOption struct {
	ID     uuid.UUID `json:"id"`
	Domain string    `json:"domain"`
}

// a.getProfileIndex lists every profile as an id and a name, unpaginated.
//
// This exists because the dashboard fills both the targets table and the profile picker.
// Paginating the one endpoint that served both at 25 rows would silently truncate the
// dropdown, leaving the 26th target unreachable with nothing on screen to explain why.
//
// It is a deliberate and narrow exception to "everything is paginated": two columns for
// even a few thousand profiles is an index-only scan and a response measured in tens of
// kilobytes, while the finding tables beside it are the ones that reach tens of thousands
// of rows.
func (a *API) getProfileIndex(w http.ResponseWriter, r *http.Request) {
	options, err := a.queries.profileIndex()
	if err != nil {
		http.Error(w, "failed to list profiles", 500)
		return
	}
	respondJSON(w, http.StatusOK, options)
}

func (a *API) createProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain   string `json:"domain"`
		Schedule string `json:"schedule"`
		Mode     string `json:"mode"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Domain == "" || req.Schedule == "" {
		http.Error(w, "domain and schedule are required", http.StatusBadRequest)
		return
	}
	if !domainPattern.MatchString(req.Domain) {
		http.Error(w, "invalid domain format", http.StatusBadRequest)
		return
	}

	// Validate the schedule before storing it. ParseSchedule was only ever called at Sync
	// time, where a failure is logged and skipped — so this endpoint accepted and stored a
	// schedule that would never fire, and answered 200.
	if _, err := scheduler.ParseSchedule(req.Schedule); err != nil {
		http.Error(w, "invalid schedule format", http.StatusBadRequest)
		return
	}

	switch req.Mode {
	case "":
		req.Mode = "full"
	case "full", "passive":
	default:
		http.Error(w, "invalid mode: expected full or passive", http.StatusBadRequest)
		return
	}

	profile := models.Profile{
		Domain:   req.Domain,
		Schedule: req.Schedule,
		Mode:     req.Mode,
		Enabled:  true,
	}

	// The unique index owns uniqueness.
	//
	// Checking for an existing row first and then inserting left a window in which two
	// requests both found nothing and both inserted, and the loser surfaced the raw driver
	// error as a 500 — so the client was told the server had broken when in fact its
	// request had simply lost a race it should have been told about with a 409.
	if err := (profiles.Service{DB: a.db}).Create(&profile); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			http.Error(w, "profile already exists", http.StatusConflict)
			return
		}
		log.Printf("[-] Creating profile %s: %v", req.Domain, err)
		http.Error(w, "failed to create profile", http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusCreated, profile)
}

func (a *API) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}
	if e := (profiles.Service{DB: a.db}).Delete(id); e != nil {
		profileError(w, e)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (a *API) editProfileSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}
	var req struct {
		Schedule string `json:"schedule"`
		Enabled  *bool  `json:"enabled"`
	}
	if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
		http.Error(w, "invalid request body", 400)
		return
	}
	if _, e := scheduler.ParseSchedule(req.Schedule); e != nil {
		http.Error(w, "invalid schedule format", 400)
		return
	}
	if e := (profiles.Service{DB: a.db}).Schedule(id, req.Schedule, req.Enabled); e != nil {
		profileError(w, e)
		return
	}
	respondJSON(w, 200, map[string]string{"schedule": req.Schedule})
}
func (a *API) forceScanProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}
	if a.queue == nil {
		http.Error(w, "scan queue unavailable", 503)
		return
	}
	if e := a.queue.Enqueue(id.String(), "manual"); e != nil {
		profileError(w, e)
		return
	}
	respondJSON(w, 202, map[string]string{"message": "scan queued"})
}
func profileError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, gorm.ErrRecordNotFound):
		http.Error(w, "profile not found", 404)
	case errors.Is(e, jobs.ErrDuplicate), errors.Is(e, profiles.ErrScanning):
		http.Error(w, e.Error(), 409)
	case errors.Is(e, jobs.ErrFull):
		w.Header().Set("Retry-After", "30")
		http.Error(w, e.Error(), 429)
	default:
		log.Printf("profile operation: %v", e)
		http.Error(w, "profile operation failed", 500)
	}
}
