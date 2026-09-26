package database

import (
	"github.com/google/uuid"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

var DB *gorm.DB

func InitDatabase(dbPath string) error {
	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	newLogger := logger.New(
		log.New(log.Writer(), "\r\n", log.LstdFlags),
		logger.Config{
			LogLevel:                  logger.Error,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
			ParameterizedQueries:      true,
		},
	)

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger:  newLogger,
		NowFunc: func() time.Time { return time.Now().UTC() },
		// Translate driver errors into gorm's own sentinels, so a unique-index violation
		// can be recognised with errors.Is rather than by matching a message string. It
		// is what lets createProfile answer 409 instead of surfacing a raw driver error
		// as a 500.
		TranslateError: true,
	})
	if err != nil {
		return err
	}

	db.Exec("PRAGMA journal_mode=WAL;")
	db.Exec("PRAGMA synchronous=NORMAL;")
	db.Exec("PRAGMA cache_size=-32000;")
	db.Exec("PRAGMA busy_timeout=5000;")
	db.Exec("PRAGMA temp_store=MEMORY;")

	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	err = db.AutoMigrate(
		&models.SchemaMigration{},
		&models.User{},
		&models.Session{},
		&models.Notification{},
		&models.Profile{},
		&models.Subdomain{},
		&models.AliveHost{},
		&models.Vulnerability{},
		&models.SecretFinding{},
		&models.DirectoryFinding{},
	)
	if err != nil {
		return err
	}

	// Legacy accounts were provisioned as administrators by ICEvirtue-admin.
	// New accounts default to viewer in BeforeCreate; only pre-role rows are upgraded.
	if err := db.Transaction(func(tx *gorm.DB) error {
		const version = "2026_09_account_roles_sessions_v1"
		var applied int64
		if err := tx.Model(&models.SchemaMigration{}).Where("version = ?", version).Count(&applied).Error; err != nil {
			return err
		}
		if applied > 0 {
			return nil
		}
		var users []models.User
		if err := tx.Unscoped().Where("public_id IS NULL OR public_id = '' OR role = ''").Find(&users).Error; err != nil {
			return err
		}
		for _, u := range users {
			updates := map[string]interface{}{}
			if u.PublicID == "" {
				updates["public_id"] = uuid.NewString()
			}
			if u.Role == "" {
				updates["role"] = "admin"
			}
			if err := tx.Unscoped().Model(&u).Updates(updates).Error; err != nil {
				return err
			}
		}
		return tx.Create(&models.SchemaMigration{Version: version}).Error
	}); err != nil {
		return err
	}

	DB = db
	log.Printf("[+] Database connected and migrated: %s", dbPath)
	return nil
}
