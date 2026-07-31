package database

import (
	"log"
	"os"
	"path/filepath"

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
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			LogLevel:                  logger.Error, 
			IgnoreRecordNotFoundError: true,         
			Colorful:                  true,        
		},
	)

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: newLogger,
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

	DB = db
	log.Printf("[+] Database connected and migrated: %s", dbPath)
	return nil
}
