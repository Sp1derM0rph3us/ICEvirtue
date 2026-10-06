package engine

import (
	"errors"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/hostkey"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"time"
)

func (run *runner) storeDirectoryBatch(p *models.Profile, rows []models.DirectoryFinding) (int, error) {
	return run.storeDirectoryObservations(p, rows, nil)
}
func (run *runner) storeDirectoryObservations(p *models.Profile, rows []models.DirectoryFinding, redirects []models.RedirectObservation) (int, error) {
	n, e := run.FindingStore.storeDirectoryObservations(p.ID, rows, redirects)
	if e != nil {
		run.rememberStorageError(e)
	}
	return n, e
}

// The caller supplies at most 100 rows of each kind. Counts, assessment transitions,
// redirects and their events share the same claim-fenced transaction.
func (run *FindingStore) storeDirectoryObservations(id uuid.UUID, rows []models.DirectoryFinding, redirects []models.RedirectObservation) (int, error) {
	total := 0
	for start := 0; start < max(len(rows), len(redirects)); start += 100 {
		confirmed, unknown, redirectChanges := 0, 0, 0
		err := run.write(func(tx *gorm.DB) error {
			for _, d := range rows[min(start, len(rows)):min(start+100, len(rows))] {
				d.ProfileID = id
				d.Host = hostkey.NormalizeOrNil(d.SubdomainURL)
				if d.Assessment == "" {
					d.Assessment = "legacy"
				}
				var old models.DirectoryFinding
				e := tx.Where("profile_id=? AND dir_url=?", id, d.DirURL).First(&old).Error
				fresh := errors.Is(e, gorm.ErrRecordNotFound)
				previousAssessment := old.Assessment
				changed := fresh || old.StatusCode != d.StatusCode || old.Assessment != d.Assessment || old.AssessmentReason != d.AssessmentReason
				if fresh {
					e = tx.Create(&d).Error
				} else if e == nil {
					e = tx.Model(&old).Updates(map[string]any{"last_seen": time.Now().UTC(), "host": d.Host, "status_code": d.StatusCode, "assessment": d.Assessment, "assessment_reason": d.AssessmentReason}).Error
				}
				if e != nil {
					return e
				}
				if d.Assessment == "confirmed" && (fresh || previousAssessment != "confirmed") {
					confirmed++
				}
				if d.Assessment == "unknown" && (fresh || previousAssessment != "unknown") {
					unknown++
				}
				if changed {
					if e = touchAsset(tx, id, d.Host); e != nil {
						return e
					}
				}
			}
			for _, r := range redirects[min(start, len(redirects)):min(start+100, len(redirects))] {
				r.ProfileID = id
				var previous models.RedirectObservation
				e := tx.Where("profile_id=? AND source_url=?", id, r.SourceURL).First(&previous).Error
				if e != nil && !errors.Is(e, gorm.ErrRecordNotFound) {
					return e
				}
				changed := errors.Is(e, gorm.ErrRecordNotFound) || previous.DestinationURL != r.DestinationURL || previous.Kind != r.Kind || previous.PreviouslyEnumerated != r.PreviouslyEnumerated || previous.StatusCode != r.StatusCode
				if changed {
					redirectChanges++
				}
				if e := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "profile_id"}, {Name: "source_url"}}, DoUpdates: clause.AssignmentColumns([]string{"host", "destination_url", "destination_host", "kind", "previously_enumerated", "status_code", "observed_at"})}).Create(&r).Error; e != nil {
					return e
				}
				host := r.Host
				if changed {
					if e := touchAsset(tx, id, &host); e != nil {
						return e
					}
				}
			}
			if e := events.Append(tx, "discovery_update", id.String(), map[string]int{"directories": confirmed, "unknown_directories": unknown, "redirects": redirectChanges}); e != nil {
				return e
			}
			if confirmed > 0 && run.job.ID != 0 {
				return tx.Model(&models.ScanRun{}).Where("id=?", run.job.RunID).UpdateColumn("new_findings", gorm.Expr("new_findings + ?", confirmed)).Error
			}
			return nil
		})
		if err != nil {
			return total, err
		}
		total += confirmed
	}
	return total, nil
}
