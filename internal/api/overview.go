package api

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type overviewProfile struct {
	IsQueued       bool       `json:"is_queued"`
	ID             uuid.UUID  `json:"id"`
	Domain         string     `json:"domain"`
	IsScanning     bool       `json:"is_scanning"`
	LastScanUTC    *time.Time `json:"last_scan_utc"`
	LastScanStatus string     `json:"last_scan_status"`
}

type overviewAssets struct {
	Total        int64 `json:"total"`
	HTTPObserved int64 `json:"http_observed"`
}

type priorityFinding struct {
	ID          uint      `json:"id"`
	Severity    string    `json:"severity"`
	Name        string    `json:"name"`
	TemplateID  string    `json:"-"`
	Host        *string   `json:"host"`
	HasAsset    bool      `json:"has_asset"`
	URL         string    `json:"url"`
	LastSeenUTC time.Time `json:"last_seen_utc" gorm:"column:last_seen"`
}

type profileOverview struct {
	Profile                 overviewProfile   `json:"profile"`
	LastIdentifiedChangeUTC *time.Time        `json:"last_identified_change_utc"`
	Assets                  overviewAssets    `json:"assets"`
	FindingSeverities       []severitySummary `json:"finding_severities"`
	PriorityFindings        []priorityFinding `json:"priority_findings"`
	DetectedWAFs            []string          `json:"detected_wafs"`
}

const overviewSeverityBucket = `CASE trim(lower(vulnerabilities.severity))
	WHEN 'critical' THEN 'critical' WHEN 'high' THEN 'high'
	WHEN 'medium' THEN 'medium' WHEN 'low' THEN 'low'
	WHEN 'info' THEN 'info' ELSE 'unknown' END`

var overviewSeverityOrder = []string{"critical", "high", "medium", "low", "info", "unknown"}

func utcOrNil(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func (a *API) getProfileOverview(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}

	result, err := a.queries.overview(id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("[-] Building overview for %s: %v", id, err)
		http.Error(w, "failed to build profile overview", http.StatusInternalServerError)
		return
	}
	respondJSON(w, http.StatusOK, result)
}
