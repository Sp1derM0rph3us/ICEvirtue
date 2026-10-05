// Package jobs owns admission, leases, fencing, and durable scan lifecycle.
package jobs

import (
	"errors"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/notifications"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"time"
)

var ErrDuplicate = errors.New("profile already has a queued or running scan")
var ErrFull = errors.New("scan queue is full")
var ErrLease = errors.New("scan ownership expired")

const Capacity = 100
const LeaseSeconds = 60
const databaseNow = "CAST(strftime('%s','now') AS INTEGER)"

type Queue struct{ DB *gorm.DB }
type Claim struct {
	Job               models.ScanJob
	Profile           models.Profile
	Config            models.ApplicationConfiguration
	DNSX, Directories []models.Wordlist
}

func (q *Queue) Enqueue(id, source string) error { return q.EnqueueScheduled(id, source, "") }
func (q *Queue) EnqueueScheduled(id, source, leaderToken string) error {
	return q.DB.Transaction(func(tx *gorm.DB) error {
		if source == "scheduled" {
			var n int64
			if e := tx.Model(&models.SchedulerLease{}).Where("id=1 AND token=? AND lease_until>"+databaseNow, leaderToken).Count(&n).Error; e != nil {
				return e
			}
			if n != 1 {
				return ErrLease
			}
		}
		var p models.Profile
		if e := tx.First(&p, "id=?", id).Error; e != nil {
			return e
		}
		if source == "scheduled" && !p.Enabled {
			return errors.New("schedule disabled")
		}
		var exists int64
		if e := tx.Model(&models.ScanJob{}).Where("profile_id=?", id).Count(&exists).Error; e != nil {
			return e
		}
		if exists > 0 {
			return ErrDuplicate
		}
		var n int64
		if e := tx.Model(&models.ScanJob{}).Where("state=?", "queued").Count(&n).Error; e != nil {
			return e
		}
		if n >= Capacity {
			return ErrFull
		}
		if e := tx.Create(&models.ScanJob{ProfileID: id, Source: source, State: "queued"}).Error; e != nil {
			return e
		}
		return events.Append(tx, "profile_update", id, nil)
	})
}
func (q *Queue) Claim(owner string) (*Claim, error) {
	var c *Claim
	err := q.DB.Transaction(func(tx *gorm.DB) error {
		config, e := appconfig.Load(tx)
		if e != nil {
			return e
		}
		var active int64
		if e = tx.Model(&models.ScanJob{}).Where("state=?", "running").Count(&active).Error; e != nil {
			return e
		}
		if active >= int64(config.Tools.MaxConcurrentScans) {
			return nil
		}
		var j models.ScanJob
		e = tx.Where("state=?", "queued").Order("id").First(&j).Error
		if errors.Is(e, gorm.ErrRecordNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		var p models.Profile
		e = tx.First(&p, "id=?", j.ProfileID).Error
		if errors.Is(e, gorm.ErrRecordNotFound) || (e == nil && j.Source == "scheduled" && !p.Enabled) {
			return tx.Delete(&j).Error
		}
		if e != nil {
			return e
		}
		j.Owner = owner
		j.Token = uuid.NewString()
		j.RunID = uuid.NewString()
		j.State = "running"
		j.Revision = config.Revision
		var now int64
		if e = tx.Raw("SELECT " + databaseNow).Scan(&now).Error; e != nil {
			return e
		}
		j.LeaseUntil = now + LeaseSeconds
		candidate := &Claim{Job: j, Profile: p, Config: config}
		if e = tx.Save(&j).Error; e != nil {
			return e
		}
		if e = tx.Create(&models.ScanRun{ID: j.RunID, ProfileID: j.ProfileID, Domain: p.Domain, Source: j.Source, Revision: j.Revision, Status: "running", StartedAt: time.Now().UTC()}).Error; e != nil {
			return e
		}
		for _, s := range []struct {
			IDs    []string
			Kind   string
			Skip   bool
			Output *[]models.Wordlist
		}{{config.Scan.DNSXWordlists, "subdomain", config.Scan.SkipDNSX, &candidate.DNSX}, {config.Scan.DirectoryWordlists, "directory", config.Scan.SkipDirectory, &candidate.Directories}} {
			if s.Skip {
				continue
			}
			for _, id := range s.IDs {
				var w models.Wordlist
				if e = tx.First(&w, "id=? AND kind=? AND state='ready'", id, s.Kind).Error; e != nil {
					if errors.Is(e, gorm.ErrRecordNotFound) {
						return finish(tx, j, "failed", "failed: configured wordlist unavailable")
					}
					return e
				}
				*s.Output = append(*s.Output, w)
				if e = tx.Create(&models.WordlistPin{JobID: j.ID, WordlistID: id}).Error; e != nil {
					return e
				}
			}
		}
		if e = notifications.Create(tx, notifications.ScanStarted, "Scan started", p.Domain+" · running in the background", "", &p.ID); e != nil {
			return e
		}
		if e = events.Append(tx, "profile_update", j.ProfileID, nil); e != nil {
			return e
		}
		c = candidate
		return nil
	})
	return c, err
}
func Fence(tx *gorm.DB, j models.ScanJob) error {
	var n int64
	if e := tx.Model(&models.ScanJob{}).Where("id=? AND token=? AND state='running' AND lease_until>"+databaseNow, j.ID, j.Token).Count(&n).Error; e != nil {
		return e
	}
	if n != 1 {
		return ErrLease
	}
	return nil
}
func (q *Queue) Renew(j models.ScanJob) error {
	r := q.DB.Model(&models.ScanJob{}).Where("id=? AND token=? AND state='running' AND lease_until>"+databaseNow, j.ID, j.Token).Update("lease_until", gorm.Expr(databaseNow+"+60"))
	if r.Error != nil {
		return r.Error
	}
	if r.RowsAffected != 1 {
		return ErrLease
	}
	return nil
}
func (q *Queue) Finish(j models.ScanJob, status, summary string) error {
	return q.DB.Transaction(func(tx *gorm.DB) error {
		if e := Fence(tx, j); e != nil {
			return e
		}
		return finish(tx, j, status, summary)
	})
}
func finish(tx *gorm.DB, j models.ScanJob, status, summary string) error {
	now := time.Now().UTC()
	if j.RunID != "" {
		if e := tx.Model(&models.ScanRun{}).Where("id=?", j.RunID).Updates(map[string]any{"status": status, "summary": summary, "finished_at": now}).Error; e != nil {
			return e
		}
		if e := tx.Model(&models.ScanStageRun{}).Where("run_id=? AND finished_at IS NULL", j.RunID).Updates(map[string]any{"status": "interrupted", "summary": "scan ended before stage completed", "finished_at": now}).Error; e != nil {
			return e
		}
	}
	if e := tx.Model(&models.ScanToolRun{}).Where("run_id=? AND status='running'", j.RunID).Updates(map[string]any{"status": "interrupted", "summary": "worker stopped before recording process exit", "finished_at": now}).Error; e != nil {
		return e
	}
	if e := tx.Model(&models.Profile{}).Where("id=?", j.ProfileID).Updates(map[string]any{"last_scan": now, "last_scan_status": summary}).Error; e != nil {
		return e
	}
	if e := tx.Where("job_id=?", j.ID).Delete(&models.WordlistPin{}).Error; e != nil {
		return e
	}
	if e := tx.Delete(&j).Error; e != nil {
		return e
	}
	kind, title := notifications.ScanFinished, "Scan finished"
	if status == "interrupted" || status == "halted" || status == "failed" {
		kind, title = notifications.ScanHalted, "Scan halted"
	}
	id, e := uuid.Parse(j.ProfileID)
	if e != nil {
		return e
	}
	if e = notifications.Create(tx, kind, title, summary, "", &id); e != nil {
		return e
	}
	return events.Append(tx, "profile_update", j.ProfileID, nil)
}
func (q *Queue) Reap() error {
	return q.DB.Transaction(func(tx *gorm.DB) error {
		var rows []models.ScanJob
		if e := tx.Where("state='running' AND lease_until<=" + databaseNow).Find(&rows).Error; e != nil {
			return e
		}
		for _, j := range rows {
			if e := finish(tx, j, "interrupted", "interrupted: worker lease expired"); e != nil {
				return e
			}
		}
		return nil
	})
}
func (q *Queue) Heartbeat(owner string) error {
	return q.DB.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id"}}, DoUpdates: clause.Assignments(map[string]any{"last_seen": gorm.Expr(databaseNow)})}).Create(&models.WorkerHeartbeat{ID: owner, LastSeen: time.Now().Unix()}).Error
}
func (q *Queue) Lead(owner, token string) (bool, error) {
	r := q.DB.Model(&models.SchedulerLease{}).Where("id=1 AND lease_until<=" + databaseNow).Updates(map[string]any{"owner": owner, "token": token, "lease_until": gorm.Expr(databaseNow + "+30")})
	return r.RowsAffected == 1, r.Error
}
func (q *Queue) RenewLeader(owner, token string) (bool, error) {
	r := q.DB.Model(&models.SchedulerLease{}).Where("id=1 AND owner=? AND token=? AND lease_until>"+databaseNow, owner, token).Update("lease_until", gorm.Expr(databaseNow+"+30"))
	return r.RowsAffected == 1, r.Error
}
func (q *Queue) ReleaseLeader(owner, token string) error {
	return q.DB.Model(&models.SchedulerLease{}).Where("id=1 AND owner=? AND token=?", owner, token).Update("lease_until", 0).Error
}

// Retention releases the writer lock between bounded groups of runs/events.
func (q *Queue) Prune() error {
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)
	for {
		removed := 0
		e := q.DB.Transaction(func(tx *gorm.DB) error {
			var ids []string
			if e := tx.Model(&models.ScanRun{}).Where("finished_at IS NOT NULL AND finished_at < ?", cutoff).Order("id").Limit(100).Pluck("id", &ids).Error; e != nil {
				return e
			}
			removed = len(ids)
			if removed == 0 {
				return nil
			}
			for _, m := range []any{&models.ScanToolRun{}, &models.ScanStageRun{}} {
				if e := tx.Where("run_id IN ?", ids).Delete(m).Error; e != nil {
					return e
				}
			}
			return tx.Where("id IN ?", ids).Delete(&models.ScanRun{}).Error
		})
		if e != nil {
			return e
		}
		if removed < 100 {
			break
		}
	}
	for {
		result := q.DB.Exec("DELETE FROM outbox_events WHERE id IN (SELECT id FROM outbox_events WHERE created_at < ? ORDER BY id LIMIT 1000)", time.Now().UTC().Add(-24*time.Hour))
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected < 1000 {
			break
		}
	}
	return q.DB.Where("last_seen < ?", time.Now().Add(-24*time.Hour).Unix()).Delete(&models.WorkerHeartbeat{}).Error
}
