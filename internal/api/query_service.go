package api

import (
	"errors"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"sort"
	"strings"
	"time"
)

// queryService owns dashboard read models. Handlers parse requests and encode responses.
type queryService struct{ db *gorm.DB }

func (s *queryService) overview(id uuid.UUID) (profileOverview, error) {
	var result profileOverview
	var profile models.Profile
	err := s.db.Transaction(func(tx *gorm.DB) error {
		// The database pool contains one connection. Every statement in this
		// transaction must use tx or it would wait for its own connection forever.
		if err := tx.First(&profile, "id = ?", id).Error; err != nil {
			return err
		}
		result.Profile = overviewProfile{
			ID: profile.ID, Domain: profile.Domain, IsScanning: profile.IsScanning, IsQueued: profile.IsQueued,
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
		var wafNames []string
		if err := tx.Model(&models.AliveHost{}).
			Distinct("waf_name").
			Where("profile_id = ? AND waf_name IS NOT NULL AND lower(waf_name) <> ?", id, "none").
			Pluck("waf_name", &wafNames).Error; err != nil {
			return err
		}
		result.DetectedWAFs = make([]string, 0, len(wafNames))
		seenWAFs := make(map[string]bool, len(wafNames))
		for _, name := range wafNames {
			name = strings.TrimSpace(name)
			key := strings.ToLower(name)
			if name != "" && !seenWAFs[key] {
				result.DetectedWAFs = append(result.DetectedWAFs, name)
				seenWAFs[key] = true
			}
		}
		sort.Slice(result.DetectedWAFs, func(i, j int) bool {
			return strings.ToLower(result.DetectedWAFs[i]) < strings.ToLower(result.DetectedWAFs[j])
		})

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

	return result, err
}

func (s *queryService) subdomains(id uuid.UUID, q listQuery, predicate string) ([]subdomainRow, PageMeta, error) {
	scope := func(db *gorm.DB) *gorm.DB {
		db = db.Where("subdomains.profile_id = ?", id)
		if predicate != "" {
			db = db.Where(predicate)
		}
		return db
	}

	var rows []subdomainRow
	var meta PageMeta

	err := s.db.Transaction(func(tx *gorm.DB) error {
		// One snapshot for the count and the page, so the total and the rows agree.
		var total int64
		if err := scope(tx.Model(&models.Subdomain{})).Count(&total).Error; err != nil {
			return err
		}

		offset, m := q.resolve(total)
		meta = m

		if sortsByVolume(q.Sort) {
			return listSubdomainsByVolume(tx, scope, q, offset, &rows)
		}
		return scope(tx.Model(&models.Subdomain{})).
			Select(subdomainSelect).
			Order(subdomainSorts[q.Sort]).
			Limit(q.Size).Offset(offset).
			Scan(&rows).Error
	})

	return rows, meta, err
}

func fetchPage[T any](service *queryService, q listQuery, model any, selectClause string, scope func(*gorm.DB) *gorm.DB, order string) ([]T, PageMeta, error) {
	var rows []T
	var meta PageMeta

	err := service.db.Transaction(func(tx *gorm.DB) error {
		// Only tx inside here. Reaching for a.db would wait for a connection
		// from a pool of exactly one that this transaction already holds, and
		// database/sql waits with no timeout: a permanent hang, not a slow query.
		var total int64
		if err := scope(tx.Model(model)).Count(&total).Error; err != nil {
			return err
		}

		offset, m := q.resolve(total)
		meta = m

		query := scope(tx.Model(model))
		if selectClause != "" {
			query = query.Select(selectClause)
		}
		return query.Order(order).Limit(q.Size).Offset(offset).Find(&rows).Error
	})

	return rows, meta, err
}

func (s *queryService) profileIndex() ([]profileOption, error) {
	var options []profileOption
	err := s.db.Model(&models.Profile{}).
		Select("profiles.id, profiles.domain").
		Order("profiles.domain ASC").
		Scan(&options).Error
	if options == nil {
		options = []profileOption{}
	}
	return options, err
}

func (s *queryService) wafs(id uuid.UUID, host string) ([]string, error) {
	var values []string
	err := s.db.Model(&models.AliveHost{}).
		Distinct("waf_name").
		Where("profile_id = ? AND host = ? AND waf_name IS NOT NULL", id, host).
		Pluck("waf_name", &values).Error
	return values, err
}

func (s *queryService) severities(id uuid.UUID, host string) ([]severitySummary, error) {
	var rows []severitySummary
	err := s.db.Model(&models.Vulnerability{}).
		Select(severityBucket+" AS severity, COUNT(*) AS count").
		Where("vulnerabilities.profile_id = ? AND vulnerabilities.host = ?", id, host).
		Group(severityBucket).
		Order(severitySummaryRank + " ASC, severity ASC").
		Scan(&rows).Error
	if rows == nil {
		rows = []severitySummary{}
	}
	return rows, err
}

func (s *queryService) workers() ([]models.WorkerHeartbeat, int64, *time.Time, error) {
	workers := []models.WorkerHeartbeat{}
	var queued int64
	var oldest *time.Time
	e := s.db.Transaction(func(tx *gorm.DB) error {
		if e := tx.Where("last_seen>?", time.Now().Add(-24*time.Hour).Unix()).Order("id").Find(&workers).Error; e != nil {
			return e
		}
		if e := tx.Model(&models.ScanJob{}).Where("state='queued'").Count(&queued).Error; e != nil {
			return e
		}
		var j models.ScanJob
		if queued > 0 {
			if e := tx.Where("state='queued'").Order("id").First(&j).Error; e != nil {
				return e
			}
			oldest = &j.CreatedAt
		}
		return nil
	})
	return workers, queued, oldest, e
}

type runHistory struct {
	Run    models.ScanRun        `json:"run"`
	Stages []models.ScanStageRun `json:"stages"`
	Tools  []models.ScanToolRun  `json:"tools"`
}

func (s *queryService) run(id string) (runHistory, error) {
	result := runHistory{Stages: []models.ScanStageRun{}, Tools: []models.ScanToolRun{}}
	e := s.db.Transaction(func(tx *gorm.DB) error {
		if e := tx.First(&result.Run, "id=?", id).Error; e != nil {
			return e
		}
		if e := tx.Where("run_id=?", id).Order("id").Find(&result.Stages).Error; e != nil {
			return e
		}
		return tx.Where("run_id=?", id).Order("id").Find(&result.Tools).Error
	})
	return result, e
}
