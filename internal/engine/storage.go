package engine

import (
	"errors"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/hostkey"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/jobs"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/notifications"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"slices"
	"time"
)

// FindingStore owns short, claim-fenced persistence transactions.
type FindingStore struct {
	db  *gorm.DB
	job models.ScanJob
}

func NewFindingStore(db *gorm.DB, job models.ScanJob) *FindingStore {
	return &FindingStore{db: db, job: job}
}

func (run *FindingStore) write(fn func(*gorm.DB) error) error {
	return run.db.Transaction(func(tx *gorm.DB) error {
		if run.job.ID != 0 {
			if e := jobs.Fence(tx, run.job); e != nil {
				return e
			}
		}
		return fn(tx)
	})
}
func touchAsset(tx *gorm.DB, id uuid.UUID, host *string) error {
	if host == nil {
		return nil
	}
	return tx.Model(&models.Subdomain{}).Where("profile_id=? AND host=?", id, *host).UpdateColumn("last_changed", time.Now().UTC()).Error
}

// Each committed batch has matching change counts and an outbox record.
func storeRows[T any](run *FindingStore, id uuid.UUID, kind string, rows []T, upsert func(*gorm.DB, T) (bool, bool, *string, error)) (int, error) {
	total := 0
	for start := 0; start < len(rows); start += 100 {
		end := min(start+100, len(rows))
		added := 0
		err := run.write(func(tx *gorm.DB) error {
			for _, row := range rows[start:end] {
				fresh, changed, host, e := upsert(tx, row)
				if e != nil {
					return e
				}
				if fresh {
					added++
				}
				if changed {
					if e = touchAsset(tx, id, host); e != nil {
						return e
					}
				}
			}
			if e := events.Append(tx, "discovery_update", id.String(), map[string]int{kind: added}); e != nil {
				return e
			}
			if added > 0 {
				if run.job.ID != 0 {
					if e := tx.Model(&models.ScanRun{}).Where("id=?", run.job.RunID).UpdateColumn("new_findings", gorm.Expr("new_findings + ?", added)).Error; e != nil {
						return e
					}
				}
				if kind == "secrets" {
					if e := notifications.Create(tx, notifications.Credentials, "New credentials found", "New credential findings are available", "", &id); e != nil {
						return e
					}
				}
			}
			return nil
		})
		if err != nil {
			return total, err
		}
		total += added
	}
	return total, nil
}
func (run *FindingStore) diffSubdomains(id *uuid.UUID, rows []string) (int, error) {
	return storeRows(run, *id, "subdomains", rows, func(tx *gorm.DB, s string) (bool, bool, *string, error) {
		var old models.Subdomain
		e := tx.Where("profile_id=? AND domain=?", *id, s).First(&old).Error
		if errors.Is(e, gorm.ErrRecordNotFound) {
			e = tx.Create(&models.Subdomain{ProfileID: *id, Domain: s}).Error
			return e == nil, false, nil, e
		}
		if e != nil {
			return false, false, nil, e
		}
		e = tx.Model(&old).Updates(map[string]any{"last_seen": time.Now().UTC(), "host": hostkey.NormalizeOrNil(s)}).Error
		return false, false, nil, e
	})
}
func (run *FindingStore) diffHosts(id *uuid.UUID, rows []models.AliveHost) (int, error) {
	return storeRows(run, *id, "hosts", rows, func(tx *gorm.DB, h models.AliveHost) (bool, bool, *string, error) {
		h.ProfileID = *id
		host := hostkey.NormalizeOrNil(h.URL)
		var old models.AliveHost
		e := tx.Where("profile_id=? AND url=?", *id, h.URL).First(&old).Error
		if errors.Is(e, gorm.ErrRecordNotFound) {
			e = tx.Create(&h).Error
			return e == nil, e == nil, host, e
		}
		if e != nil {
			return false, false, host, e
		}
		changed := old.IP != h.IP || old.Title != h.Title || old.WebServer != h.WebServer || old.StatusCode != h.StatusCode
		e = tx.Model(&old).Updates(map[string]any{"last_seen": time.Now().UTC(), "host": host, "ip": h.IP, "title": h.Title, "web_server": h.WebServer, "status_code": h.StatusCode}).Error
		return false, changed, host, e
	})
}
func (run *FindingStore) diffWAFs(id *uuid.UUID, rows []wafObservation) (int, error) {
	return storeRows(run, *id, "wafs", rows, func(tx *gorm.DB, w wafObservation) (bool, bool, *string, error) {
		host := hostkey.NormalizeOrNil(w.URL)
		var old models.AliveHost
		e := tx.Where("profile_id=? AND url=?", *id, w.URL).First(&old).Error
		if e != nil {
			return false, false, host, e
		}
		if old.WAFName != nil && *old.WAFName == w.Name {
			return false, false, host, nil
		}
		previous := ""
		if old.WAFName != nil {
			previous = *old.WAFName
		}
		changed := w.Name != "none" || (previous != "" && previous != "none")
		e = tx.Model(&old).UpdateColumn("waf_name", w.Name).Error
		return changed, changed, host, e
	})
}
func (run *FindingStore) diffVulns(id *uuid.UUID, rows []models.Vulnerability) (int, error) {
	return storeRows(run, *id, "vulnerabilities", rows, func(tx *gorm.DB, v models.Vulnerability) (bool, bool, *string, error) {
		v.ProfileID = *id
		host := hostkey.NormalizeOrNil(v.URL)
		var old models.Vulnerability
		e := tx.Where("profile_id=? AND template_id=? AND url=?", *id, v.TemplateID, v.URL).First(&old).Error
		if errors.Is(e, gorm.ErrRecordNotFound) {
			e = tx.Create(&v).Error
			return e == nil, e == nil, host, e
		}
		if e != nil {
			return false, false, host, e
		}
		changed := old.Severity != v.Severity || old.Name != v.Name || old.Description != v.Description
		e = tx.Model(&old).Updates(map[string]any{"last_seen": time.Now().UTC(), "host": host, "severity": v.Severity, "name": v.Name, "description": v.Description}).Error
		return false, changed, host, e
	})
}
func (run *FindingStore) diffDirectories(id *uuid.UUID, rows []models.DirectoryFinding) (int, error) {
	return storeRows(run, *id, "directories", rows, func(tx *gorm.DB, d models.DirectoryFinding) (bool, bool, *string, error) {
		d.ProfileID = *id
		host := hostkey.NormalizeOrNil(d.SubdomainURL)
		var old models.DirectoryFinding
		e := tx.Where("profile_id=? AND dir_url=?", *id, d.DirURL).First(&old).Error
		if errors.Is(e, gorm.ErrRecordNotFound) {
			e = tx.Create(&d).Error
			return e == nil, e == nil, host, e
		}
		if e != nil {
			return false, false, host, e
		}
		changed := old.StatusCode != d.StatusCode
		e = tx.Model(&old).Updates(map[string]any{"last_seen": time.Now().UTC(), "host": host, "status_code": d.StatusCode}).Error
		return false, changed, host, e
	})
}
func (run *FindingStore) diffSecrets(id *uuid.UUID, rows []models.SecretFinding) (int, error) {
	return storeRows(run, *id, "secrets", rows, func(tx *gorm.DB, s models.SecretFinding) (bool, bool, *string, error) {
		s.ProfileID = *id
		host := hostkey.NormalizeOrNil(s.SourceURL)
		var old models.SecretFinding
		e := tx.Where("profile_id=? AND source_url=? AND secret_type=? AND secret_value=?", *id, s.SourceURL, s.SecretType, s.SecretValue).First(&old).Error
		if errors.Is(e, gorm.ErrRecordNotFound) {
			counterpart := "Mantra"
			if s.Engine == "Mantra" {
				counterpart = "SecretHound"
			}
			var other models.SecretFinding
			oe := tx.Where("profile_id=? AND source_url=? AND secret_value=? AND engine=?", *id, s.SourceURL, s.SecretValue, counterpart).First(&other).Error
			if oe != nil && !errors.Is(oe, gorm.ErrRecordNotFound) {
				return false, false, host, oe
			}
			if oe == nil {
				if s.Engine == "Mantra" {
					e = tx.Model(&other).Updates(map[string]any{"last_seen": time.Now().UTC(), "seen_live": other.SeenLive || s.SeenLive}).Error
					return false, !other.SeenLive && s.SeenLive, host, e
				}
				s.SeenLive = s.SeenLive || other.SeenLive
			}
			e = tx.Create(&s).Error
			return e == nil, e == nil, host, e
		}
		if e != nil {
			return false, false, host, e
		}
		if old.Engine == "SecretHound" && s.Engine == "Mantra" {
			e = tx.Model(&old).Updates(map[string]any{"last_seen": time.Now().UTC(), "seen_live": old.SeenLive || s.SeenLive}).Error
			return false, !old.SeenLive && s.SeenLive, host, e
		}
		changed := old.Engine != s.Engine || old.Risk != s.Risk || old.Description != s.Description || old.Occurrences != s.Occurrences || !slices.Equal(old.Context, s.Context) || (old.ArchiveURL == "" && s.ArchiveURL != "") || (!old.SeenLive && s.SeenLive)
		if old.ArchiveURL == "" {
			old.ArchiveURL = s.ArchiveURL
		}
		old.SeenLive = old.SeenLive || s.SeenLive
		old.Engine = s.Engine
		old.Risk = s.Risk
		old.Description = s.Description
		old.Context = s.Context
		old.Occurrences = s.Occurrences
		return false, changed, host, tx.Save(&old).Error
	})
}
func (run *FindingStore) persistSubdomains(p *models.Profile, v []string) (int, error) {
	return run.diffSubdomains(&p.ID, v)
}
func (run *FindingStore) persistHosts(p *models.Profile, v []models.AliveHost) (int, error) {
	return run.diffHosts(&p.ID, v)
}
func (run *FindingStore) persistWAFs(p *models.Profile, v []wafObservation) (int, error) {
	return run.diffWAFs(&p.ID, v)
}
func (run *FindingStore) persistVulns(p *models.Profile, v []models.Vulnerability) (int, error) {
	return run.diffVulns(&p.ID, v)
}
func (run *FindingStore) persistDirectories(p *models.Profile, v []models.DirectoryFinding) (int, error) {
	return run.diffDirectories(&p.ID, v)
}
func (run *FindingStore) persistSecrets(p *models.Profile, v []models.SecretFinding) (int, error) {
	return run.diffSecrets(&p.ID, v)
}
