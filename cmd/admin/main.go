package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/access"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/accounts"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Expected 'create' subcommand")
		os.Exit(1)
	}

	userCmd := flag.NewFlagSet("create", flag.ExitOnError)
	username := userCmd.String("username", "", "Username for the admin")
	password := userCmd.String("password", "", "Password for the admin")
	dbPathFlag := userCmd.String("db-path", "", "Path to the database file")

	switch os.Args[1] {
	case "create":
		userCmd.Parse(os.Args[2:])
		if *username == "" || *password == "" {
			fmt.Println("Both --username and --password are required.")
			os.Exit(1)
		}

		var dbPath string
		if *dbPathFlag != "" {
			dbPath = *dbPathFlag
		} else {
			cwd, err := os.Getwd()
			if err != nil {
				log.Fatalf("[-] Failed to get current working directory: %v", err)
			}
			dbPath = filepath.Join(cwd, "icevirtue.db")
		}

		err := database.InitDatabase(dbPath)
		if err != nil {
			log.Fatalf("[-] Failed to initialize database: %v", err)
		}

		if err := createAdmin(database.DB, *username, *password); err != nil {
			log.Fatalf("[-] Failed to create admin user: %v", err)
		}

		fmt.Printf("[+] Successfully created admin account: %s\n", *username)

	default:
		fmt.Println("Expected 'create' subcommand")
		os.Exit(1)
	}
}

// createAdmin uses the same input rules as the web dashboard. The User model's
// BeforeCreate hook supplies the opaque public ID and initial auth version used
// by dashboard sessions.
func createAdmin(db *gorm.DB, username, password string) error {
	if err := accounts.ValidateUsername(username); err != nil {
		return err
	}
	hash, err := accounts.HashPasswordWithPolicy(db, password)
	if err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := accounts.CheckPassword(tx, password); err != nil {
			return err
		}
		return tx.Create(&models.User{
			Username:     username,
			PasswordHash: hash,
			Role:         access.Admin,
		}).Error
	})
}
