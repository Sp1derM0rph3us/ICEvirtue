package api

import (
	"errors"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
	"net/http"
	"time"
)

func (a *API) listRuns(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}
	sorts := map[string]string{"latest": "started_at DESC, id DESC"}
	q := parseListQuery(r, 25, sorts, "latest")
	listPage[models.ScanRun](a.queries, w, q, &models.ScanRun{}, "", func(db *gorm.DB) *gorm.DB { return db.Where("profile_id=?", id.String()) }, sorts["latest"])
}
func (a *API) getRun(w http.ResponseWriter, r *http.Request) {
	result, e := a.queries.run(chi.URLParam(r, "runID"))
	if errors.Is(e, gorm.ErrRecordNotFound) {
		http.Error(w, "run not found", 404)
		return
	}
	if e != nil {
		http.Error(w, "run history unavailable", 500)
		return
	}
	respondJSON(w, 200, result)
}

func (a *API) workerStatus(w http.ResponseWriter, r *http.Request) {
	workers, queued, oldest, e := a.queries.workers()
	if e != nil {
		http.Error(w, "worker status unavailable", 500)
		return
	}
	age := 0
	if oldest != nil {
		age = max(0, int(time.Since(*oldest).Seconds()))
	}
	status := make([]map[string]any, 0, len(workers))
	for _, worker := range workers {
		status = append(status, map[string]any{"id": worker.ID, "last_seen": worker.LastSeen, "online": worker.LastSeen > time.Now().Add(-30*time.Second).Unix()})
	}
	respondJSON(w, 200, map[string]any{"workers": status, "queue_depth": queued, "oldest_queued_seconds": age})
}
