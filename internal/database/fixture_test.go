package database

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDatabase(path string) error {
	s, e := Open(path, true)
	if e == nil {
		DB = s.DB
		DB.Where("version IN ?", []string{hostCorrelationV1, subdomainLastChangedV1, timestampsUTCV1, secretLiveEvidenceV1, toolTimeoutsV1}).Delete(&models.SchemaMigration{})
	}
	return e
}
func RunDataMigrations() error        { return (&Store{DB: DB}).RunDataMigrations() }
func runToolTimeoutsMigration() error { return (&Store{DB: DB}).runToolTimeoutsMigration() }
