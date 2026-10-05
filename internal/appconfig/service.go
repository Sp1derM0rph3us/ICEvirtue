package appconfig

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
)

func SaveSection(db *gorm.DB, authorize func(*gorm.DB) error, actor string, revision uint64, settings any) (models.ApplicationConfiguration, error) {
	var c models.ApplicationConfiguration
	err := db.Transaction(func(tx *gorm.DB) error {
		if e := authorize(tx); e != nil {
			return e
		}
		var e error
		c, e = Load(tx)
		if e != nil {
			return e
		}
		switch v := settings.(type) {
		case *models.PasswordPolicy:
			c.Password = *v
		case *models.ScanSettings:
			c.Scan = *v
		case *models.ToolSettings:
			c.Tools = *v
		}
		c.UpdatedBy = actor
		return Save(tx, &c, revision)
	})
	return c, err
}

func Reset(db *gorm.DB, authorize func(*gorm.DB) error, actor string) (models.ApplicationConfiguration, error) {
	var c models.ApplicationConfiguration
	err := db.Transaction(func(tx *gorm.DB) error {
		if e := authorize(tx); e != nil {
			return e
		}
		current, e := Load(tx)
		if e != nil {
			return e
		}
		c = Defaults()
		c.Revision = current.Revision
		c.UpdatedBy = actor
		return Save(tx, &c, current.Revision)
	})
	return c, err
}
