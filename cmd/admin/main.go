package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/access"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/accounts"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Expected 'create' subcommand")
		os.Exit(1)
	}

	userCmd := flag.NewFlagSet("create", flag.ExitOnError)
	username := userCmd.String("username", "", "Username for the admin")
	password := userCmd.String("password", "", "Password for the admin")
	role := userCmd.String("role", access.Admin, "Account role: viewer, operator, admin (default admin)")
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

		if !access.ValidRole(*role) {
			log.Fatal("invalid role")
		}
		if err := accounts.ValidateUsername(*username); err != nil {
			log.Fatal(err)
		}
		hash, err := accounts.HashPassword(*password)
		if err != nil {
			log.Fatalf("[-] Failed to hash password: %v", err)
		}

		user := models.User{
			Username:     *username,
			PasswordHash: hash,
			Role:         *role,
		}

		result := database.DB.Create(&user)
		if result.Error != nil {
			log.Fatalf("[-] Failed to create user (might already exist): %v", result.Error)
		}

		fmt.Printf("[+] Successfully created %s account: %s\n", *role, *username)

	default:
		fmt.Println("Expected 'create' subcommand")
		os.Exit(1)
	}
}
