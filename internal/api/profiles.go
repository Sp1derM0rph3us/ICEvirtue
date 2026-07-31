package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/engine"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/scheduler"
)

// The one rule that governs every transaction in this file:
//
//	Inside Transaction(func(tx *gorm.DB)), use only tx.
//
// database.go sets SetMaxOpenConns(1), so a call through the package-level database.DB
// inside a transaction callback waits for a connection from a pool of exactly one that
// the transaction itself is holding — and database/sql waits with no timeout. That is a
// permanent hang, not a slow query, and busy_timeout does not help because the block is
// in Go. The same applies to Sync(), which reads the database and therefore stays outside.

// domainPattern is compiled once. It used to be compiled on every request.
var domainPattern = regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

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
// This exists because the dashboard fills both the targets table and the profile picker.
// Paginating the one endpoint that served both at 25 rows would silently truncate the
// dropdown, leaving the 26th target unreachable with nothing on screen to explain why.
//
// It is a deliberate and narrow exception to "everything is paginated": two columns for
// even a few thousand profiles is an index-only scan and a response measured in tens of
// kilobytes, while the finding tables beside it are the ones that reach tens of thousands
// of rows.
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

	if req.Mode == "" {
		req.Mode = "full"
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
	if err := database.DB.Create(&profile).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			http.Error(w, "profile already exists", http.StatusConflict)
			return
		}
		log.Printf("[-] Creating profile %s: %v", req.Domain, err)
		http.Error(w, "failed to create profile", http.StatusInternalServerError)
		return
	}

	a.syncScheduler("after creating " + profile.Domain)
	respondJSON(w, http.StatusCreated, profile)
}

func (a *API) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}

	// Take the same lock a scan takes, rather than reading is_scanning and trusting it.
	//
	// A plain read leaves the window in which a scheduled run claims the lock between the
	// check and the first DELETE, and then writes findings for a profile that no longer
	// exists — recreating exactly the orphaned rows this handler exists to prevent.
	claim := database.DB.Model(&models.Profile{}).
		Where("id = ? AND is_scanning = ?", id, false).
		Update("is_scanning", true)
	if claim.Error != nil {
		log.Printf("[-] Claiming profile %s for deletion: %v", id, claim.Error)
		http.Error(w, "failed to delete profile", http.StatusInternalServerError)
		return
	}
	if claim.RowsAffected == 0 {
		var exists int64
		database.DB.Model(&models.Profile{}).Where("id = ?", id).Count(&exists)
		if exists == 0 {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}
		// A scan cannot be cancelled: OrchestrateScan has no cancellation path, so
		// refusing is the honest answer, exactly as forceScanProfile refuses a second
		// concurrent run. Giving delete the ability to cancel a run is a separate change.
		http.Error(w, "profile is scanning; try again when the run finishes", http.StatusConflict)
		return
	}

	// From here the lock is held. Anything that goes wrong below has to give it back, or
	// the profile is stuck refusing both scans and deletes forever. This runs outside the
	// transaction on purpose: inside, a rollback would undo the release too.
	deleted := false
	defer func() {
		if !deleted {
			database.DB.Model(&models.Profile{}).Where("id = ?", id).Update("is_scanning", false)
		}
	}()

	err := database.DB.Transaction(func(tx *gorm.DB) error {
		// Unscoped, because every child model carries gorm.DeletedAt and a plain Delete
		// only sets deleted_at. Those rows were surviving every delete — invisible to the
		// scoped queries the dashboard uses, but still in the file, owned by a profile
		// that no longer existed. That is precisely the orphaned data this handler claims
		// to prevent, and the previous test counted without Unscoped() so it passed over
		// the bug.
		children := []interface{}{
			&models.Subdomain{}, &models.AliveHost{}, &models.Vulnerability{},
			&models.SecretFinding{}, &models.DirectoryFinding{},
		}
		for _, child := range children {
			// Errors are checked now. Before, all five statements discarded their result,
			// so a failed delete was indistinguishable from a successful one and the
			// handler still answered 204.
			if err := tx.Unscoped().Where("profile_id = ?", id).Delete(child).Error; err != nil {
				return err
			}
		}
		return tx.Unscoped().Where("id = ?", id).Delete(&models.Profile{}).Error
	})
	if err != nil {
		log.Printf("[-] Deleting profile %s: %v", id, err)
		http.Error(w, "failed to delete profile", http.StatusInternalServerError)
		return
	}
	deleted = true

	// After the commit, never inside it: Sync reads the database.
	a.syncScheduler("after deleting " + id.String())

	events.Broadcast("profile_update", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) editProfileSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}

	var req struct {
		Schedule string `json:"schedule"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Schedule == "" {
		http.Error(w, "schedule is required", http.StatusBadRequest)
		return
	}
	if _, err := scheduler.ParseSchedule(req.Schedule); err != nil {
		http.Error(w, "invalid schedule format", http.StatusBadRequest)
		return
	}

	// One statement, no read-then-write. The old handler loaded the profile, updated the
	// column, and then returned profile.Schedule from the struct it had loaded before the
	// update — so the response always echoed the previous value.
	res := database.DB.Model(&models.Profile{}).
		Where("id = ?", id).
		Update("schedule", req.Schedule)
	if res.Error != nil {
		log.Printf("[-] Updating the schedule for %s: %v", id, res.Error)
		http.Error(w, "failed to update schedule", http.StatusInternalServerError)
		return
	}
	// SQLite counts a row as changed whenever an UPDATE touches it, even when the new
	// value equals the old, so zero rows here means no such profile — which also covers it
	// having been deleted concurrently. This reasoning is SQLite-specific.
	if res.RowsAffected == 0 {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}

	a.syncScheduler("after rescheduling " + id.String())

	// Return the value that was written. Re-reading would be no more truthful under a
	// concurrent writer, and this is what the caller's request achieved.
	respondJSON(w, http.StatusOK, map[string]string{"schedule": req.Schedule})
}

func forceScanProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}

	var profile models.Profile
	if err := database.DB.First(&profile, id).Error; err != nil {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}

	// Optimistic pre-check so the obvious case (double-clicking Initiate) gets a 409
	// instead of a 202 that quietly does nothing. It is NOT the guard against concurrent
	// runs: OrchestrateScan claims the lock atomically and is the only authority on
	// whether a run actually starts.
	if profile.IsScanning {
		http.Error(w, "profile is already scanning", http.StatusConflict)
		return
	}

	go engine.OrchestrateScan(&profile)

	respondJSON(w, http.StatusAccepted, map[string]string{"message": "scan started in background"})
}

// syncScheduler resynchronises and logs a failure without failing the request.
//
// The write has already committed. Returning an error now would tell the client its
// create or delete had not happened when it had; the real consequence of a failed sync is
// a stale schedule, which belongs in the log. The three call sites used to discard this
// error entirely.
func (a *API) syncScheduler(context string) {
	if a.sched == nil {
		return
	}
	if err := a.sched.Sync(); err != nil {
		log.Printf("[-] Scheduler sync %s failed; the schedule may be stale until the next restart: %v",
			context, err)
	}
}
