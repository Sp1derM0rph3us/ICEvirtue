package api

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type overviewProfile struct {
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

func getProfileOverview(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}

	var result profileOverview
	var profile models.Profile
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		// The database pool contains one connection. Every statement in this
		// transaction must use tx or it would wait for its own connection forever.
		if err := tx.First(&profile, "id = ?", id).Error; err != nil {
			return err
		}
		result.Profile = overviewProfile{
			ID: profile.ID, Domain: profile.Domain, IsScanning: profile.IsScanning,
			LastScanUTC: utcOrNil(profile.LastScan), LastScanStatus: profile.LastScanStatus,
		}

		assets := tx.Model(&models.Subdomain{}).Where("subdomains.profile_id = ?", id)
		if err := assets.Count(&result.Assets.Total).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.Subdomain{}).
			Where("subdomains.profile_id = ?", id).
			Where(`EXISTS (SELECT 1 FROM alive_hosts a
				WHERE a.profile_id = subdomains.profile_id
				AND a.host = subdomains.host AND a.deleted_at IS NULL)`).
			Count(&result.Assets.HTTPObserved).Error; err != nil {
			return err
		}

		var latest models.Subdomain
		err := tx.Model(&models.Subdomain{}).Select("last_changed").
			Where("profile_id = ?", id).
			Order("julianday(last_changed) DESC, subdomains.id DESC").Take(&latest).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil {
			result.LastIdentifiedChangeUTC = utcOrNil(latest.LastChanged)
		}

		var severities []severitySummary
		if err := tx.Model(&models.Vulnerability{}).
			Select(overviewSeverityBucket+" AS severity, COUNT(*) AS count").
			Where("vulnerabilities.profile_id = ?", id).
			Group(overviewSeverityBucket).Scan(&severities).Error; err != nil {
			return err
		}
		counts := make(map[string]int64, len(severities))
		for _, item := range severities {
			counts[item.Severity] = item.Count
		}
		result.FindingSeverities = make([]severitySummary, 0, len(overviewSeverityOrder))
		for _, severity := range overviewSeverityOrder {
			result.FindingSeverities = append(result.FindingSeverities,
				severitySummary{Severity: severity, Count: counts[severity]})
		}

		var findings []priorityFinding
		if err := tx.Model(&models.Vulnerability{}).
			Select(`vulnerabilities.id, vulnerabilities.severity, vulnerabilities.name,
				vulnerabilities.template_id, vulnerabilities.host, vulnerabilities.url,
				vulnerabilities.last_seen,
				EXISTS (SELECT 1 FROM subdomains s WHERE s.profile_id = vulnerabilities.profile_id
					AND s.host = vulnerabilities.host AND s.deleted_at IS NULL) AS has_asset`).
			Where("vulnerabilities.profile_id = ?", id).
			Where("trim(lower(vulnerabilities.severity)) IN ('critical', 'high')").
			Order("CASE trim(lower(vulnerabilities.severity)) WHEN 'critical' THEN 0 ELSE 1 END").
			Order("vulnerabilities.id DESC").Limit(8).Scan(&findings).Error; err != nil {
			return err
		}
		if findings == nil {
			findings = []priorityFinding{}
		}
		result.PriorityFindings = findings
		for i := range result.PriorityFindings {
			finding := &result.PriorityFindings[i]
			finding.Severity = strings.ToLower(strings.TrimSpace(finding.Severity))
			if strings.TrimSpace(finding.Name) == "" {
				finding.Name = finding.TemplateID
			}
			finding.LastSeenUTC = finding.LastSeenUTC.UTC()
		}
		return nil
	})
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
