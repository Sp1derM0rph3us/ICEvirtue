package api

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/hostkey"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"net/http"
)

type redirectSummary struct {
	DestinationHost      string `json:"destination_host"`
	Kind                 string `json:"kind"`
	PreviouslyEnumerated bool   `json:"previously_enumerated"`
	Count                int    `json:"count"`
}

func (s *queryService) redirectSummary(id uuid.UUID, host string, kind string) ([]redirectSummary, error) {
	rows := []redirectSummary{}
	q := s.db.Model(&models.RedirectObservation{}).Where("profile_id=? AND host=?", id, host)
	if kind == "cross_host" || kind == "cross_scope" {
		q = q.Where("kind=?", kind)
	}
	err := q.Select("destination_host,kind,previously_enumerated,COUNT(*) AS count").Group("destination_host,kind,previously_enumerated").Order("count DESC, destination_host ASC, kind ASC, previously_enumerated ASC").Limit(6).Scan(&rows).Error
	return rows, err
}
func (a *API) getRedirectSummary(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}
	host := hostkey.Normalize(r.URL.Query().Get("host"))
	if host == "" {
		respondJSON(w, 200, []redirectSummary{})
		return
	}
	rows, err := a.queries.redirectSummary(id, host, r.URL.Query().Get("kind"))
	if err != nil {
		http.Error(w, "failed to summarize redirects", 500)
		return
	}
	respondJSON(w, 200, rows)
}
func (a *API) getProfileRedirects(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}
	sorts := map[string]string{"latest": "observed_at DESC, id DESC"}
	q := parseListQuery(r, 25, sorts, "latest")
	if q.Host == "" {
		respondJSON(w, 200, emptyPage[models.RedirectObservation](q))
		return
	}
	kind := r.URL.Query().Get("kind")
	listPage[models.RedirectObservation](a.queries, w, q, &models.RedirectObservation{}, "", func(db *gorm.DB) *gorm.DB {
		db = db.Where("profile_id=? AND host=?", id, q.Host)
		if kind == "cross_host" || kind == "cross_scope" {
			db = db.Where("kind=?", kind)
		}
		return db
	}, sorts["latest"])
}
