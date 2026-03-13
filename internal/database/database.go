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
	})
	if err != nil {
		return err
	}

	db.Exec("PRAGMA journal_mode=WAL;")

	err = db.AutoMigrate(
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
