package profiles

import (
	"errors"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/notifications"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrScanning = errors.New("profile is scanning; try again when the run finishes")

type Service struct{ DB *gorm.DB }

func (s Service) Create(p *models.Profile) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		if e := tx.Create(p).Error; e != nil {
			return e
		}
		return events.Append(tx, "profile_update", p.ID.String(), nil)
	})
}
func (s Service) Delete(id uuid.UUID) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		var p models.Profile
		if e := tx.First(&p, "id=?", id).Error; e != nil {
			return e
		}
		if p.IsScanning {
			return ErrScanning
		}
		if e := tx.Where("profile_id=?", id.String()).Delete(&models.ScanJob{}).Error; e != nil {
			return e
		}
		runs := tx.Model(&models.ScanRun{}).Select("id").Where("profile_id=?", id.String())
		for _, m := range []any{&models.ScanToolRun{}, &models.ScanStageRun{}} {
			if e := tx.Where("run_id IN (?)", runs).Delete(m).Error; e != nil {
				return e
			}
		}
		if e := tx.Where("profile_id=?", id.String()).Delete(&models.ScanRun{}).Error; e != nil {
			return e
		}
		for _, m := range []any{&models.Subdomain{}, &models.AliveHost{}, &models.Vulnerability{}, &models.SecretFinding{}, &models.DirectoryFinding{}, &models.RedirectObservation{}} {
			if e := tx.Unscoped().Where("profile_id=?", id).Delete(m).Error; e != nil {
				return e
			}
		}
		if e := tx.Unscoped().Delete(&p).Error; e != nil {
			return e
		}
		if e := notifications.Create(tx, notifications.ProfileDeleted, "Profile deleted", p.Domain+" and its findings were removed", p.Domain, nil); e != nil {
			return e
		}
		return events.Append(tx, "profile_update", id.String(), nil)
	})
}
func (s Service) Schedule(id uuid.UUID, schedule string, enabled *bool) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		var p models.Profile
		if e := tx.First(&p, "id=?", id).Error; e != nil {
			return e
		}
		values := map[string]any{"schedule": schedule}
		if enabled != nil {
			values["enabled"] = *enabled
			if !*enabled {
				if e := tx.Where("profile_id=? AND state='queued' AND source='scheduled'", id.String()).Delete(&models.ScanJob{}).Error; e != nil {
					return e
				}
			}
		}
		if e := tx.Model(&p).Updates(values).Error; e != nil {
			return e
		}
		return events.Append(tx, "profile_update", id.String(), nil)
	})
}
