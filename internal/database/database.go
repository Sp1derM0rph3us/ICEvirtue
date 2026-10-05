package database

import (
	"fmt"
	"github.com/google/uuid"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type Store struct{ DB *gorm.DB }

func Open(dbPath string, migrate bool) (*Store, error) {
	if !migrate {
		if _, err := os.Stat(dbPath); err != nil {
			return nil, fmt.Errorf("start ICEvirtue server to initialize database: %w", err)
		}
	}
	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
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

	db, err := gorm.Open(sqlite.Open("file:"+(&url.URL{Path: dbPath}).EscapedPath()+"?_txlock=immediate&_pragma=busy_timeout(5000)"), &gorm.Config{
		Logger:  newLogger,
		NowFunc: func() time.Time { return time.Now().UTC() },
		// Translate driver errors into gorm's own sentinels, so a unique-index violation
		// can be recognised with errors.Is rather than by matching a message string. It
		// is what lets createProfile answer 409 instead of surfacing a raw driver error
		// as a 500.
		TranslateError: true,
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	ok := false
	defer func() {
		if !ok {
			sqlDB.Close()
		}
	}()
	for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL", "PRAGMA cache_size=-32000", "PRAGMA temp_store=MEMORY"} {
		if err := db.Exec(pragma).Error; err != nil {
			return nil, err
		}
	}
	store := &Store{DB: db}
	var n int64
	ready := db.Migrator().HasTable(&models.SchemaMigration{}) && db.Model(&models.SchemaMigration{}).Where("version = ?", models.ModularitySchema).Count(&n).Error == nil && n == 1
	if !migrate {
		if !ready {
			return nil, fmt.Errorf("database requires migration; start ICEvirtue server before workers")
		}
		ok = true
		return store, nil
	}
	if ready {
		ok = true
		return store, nil
	}
	err = db.AutoMigrate(
		&models.ApplicationConfiguration{}, &models.Wordlist{}, &models.ScanJob{}, &models.WordlistPin{},
		&models.SchemaMigration{}, &models.ScanRun{}, &models.ScanStageRun{}, &models.ScanToolRun{}, &models.WorkerHeartbeat{}, &models.SchedulerLease{}, &models.OutboxEvent{},
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
		return nil, err
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
		return nil, err
	}

	if err := appconfig.Seed(db); err != nil {
		return nil, err
	}
	if err := store.RunDataMigrations(); err != nil {
		return nil, err
	}
	if err := store.migrateWorkers(); err != nil {
		return nil, err
	}
	ok = true
	log.Printf("[+] Database connected and migrated: %s", dbPath)
	return store, nil
}

func (s *Store) Close() error {
	db, err := s.DB.DB()
	if err != nil {
		return err
	}
	return db.Close()
}
func (s *Store) migrateWorkers() error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.Profile{}).Where("id IN (SELECT profile_id FROM scan_jobs WHERE state = 'running')").Update("last_scan_status", "interrupted: upgrade").Error; err != nil {
			return err
		}
		if err := tx.Where("state = ?", "running").Delete(&models.ScanJob{}).Error; err != nil {
			return err
		}
		if err := tx.Where("1=1").Delete(&models.WordlistPin{}).Error; err != nil {
			return err
		}
		for _, column := range []string{"is_scanning", "is_queued"} {
			if tx.Migrator().HasColumn("profiles", column) {
				if err := tx.Exec("ALTER TABLE profiles DROP COLUMN " + column).Error; err != nil {
					return err
				}
			}
		}
		if err := tx.Create(&models.SchedulerLease{ID: 1}).Error; err != nil {
			return err
		}
		return tx.Create(&models.SchemaMigration{Version: models.ModularitySchema}).Error
	})
}
