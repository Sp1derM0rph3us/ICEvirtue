package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/access"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/accounts"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return fmt.Errorf("expected 'create' subcommand")
	}
	flags := flag.NewFlagSet("create", flag.ContinueOnError)
	username := flags.String("username", "", "Username for the admin")
	password := flags.String("password", "", "Password for the admin")
	path := flags.String("db-path", "icevirtue.db", "Server-initialized SQLite database")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *username == "" || *password == "" {
		return fmt.Errorf("both --username and --password are required")
	}
	store, err := database.Open(*path, false)
	if err != nil {
		return err
	}
	defer store.Close()
	if err = createAdmin(store.DB, *username, *password); err != nil {
		return err
	}
	fmt.Printf("[+] Successfully created admin account: %s\n", *username)
	return nil
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
