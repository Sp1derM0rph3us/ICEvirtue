package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"

	"golang.org/x/crypto/bcrypt"
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

		hash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("[-] Failed to hash password: %v", err)
		}

		user := models.User{
			Username:     *username,
			PasswordHash: string(hash),
		}

		result := database.DB.Create(&user)
		if result.Error != nil {
			log.Fatalf("[-] Failed to create user (might already exist): %v", result.Error)
		}

		fmt.Printf("[+] Successfully created system administrator: %s\n", *username)

	default:
		fmt.Println("Expected 'create' subcommand")
		os.Exit(1)
	}
}
