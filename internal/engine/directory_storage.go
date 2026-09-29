package engine

import (
	"errors"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/hostkey"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
)

// A failed batch is rolled back and reported; scans must not claim that findings
// were saved after a disk-full or database error.
func (run *runner) storeDirectoryBatch(profile *models.Profile, batch []models.DirectoryFinding) (int, error) {
	added := 0
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		for _, finding := range batch {
			var old models.DirectoryFinding
			err := tx.Where("profile_id = ? AND dir_url = ?", profile.ID, finding.DirURL).First(&old).Error
			changed := false
			if errors.Is(err, gorm.ErrRecordNotFound) {
				if err = tx.Create(&finding).Error; err != nil {
					return err
				}
				added++
				changed = true
			} else if err != nil {
				return err
			} else {
				changed = old.StatusCode != finding.StatusCode
				if err = tx.Model(&old).Updates(map[string]any{"last_seen": gorm.Expr("CURRENT_TIMESTAMP"), "status_code": finding.StatusCode, "host": hostkey.NormalizeOrNil(finding.SubdomainURL)}).Error; err != nil {
					return err
				}
			}
			if changed {
				if host := hostkey.NormalizeOrNil(finding.SubdomainURL); host != nil {
					if err = tx.Model(&models.Subdomain{}).Where("profile_id = ? AND host = ?", profile.ID, *host).UpdateColumn("last_changed", gorm.Expr("CURRENT_TIMESTAMP")).Error; err != nil {
						return err
					}
				}
			}
			if run.config.Scan.Verbose {
				logf("[VERBOSE] Directory observed: %s (%d)", finding.DirURL, finding.StatusCode)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return broadcastIfNew(profile, "directories", added), nil
}
