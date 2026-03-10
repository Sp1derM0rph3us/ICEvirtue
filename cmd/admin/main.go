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

	switch os.Args[1] {
	case "create":
		userCmd.Parse(os.Args[2:])
		if *username == "" || *password == "" {
			fmt.Println("Both --username and --password are required.")
			os.Exit(1)
		}

		dbPath := "icevirtue.db"
		if _, err := os.Stat("../../go.mod"); err == nil {
			dbPath = filepath.Join("..", "..", "icevirtue.db")
		} else if _, err := os.Stat("go.mod"); err == nil {
			dbPath = "icevirtue.db" 
		} else {
			ex, err := os.Executable()
			if err == nil {
				dbPath = filepath.Join(filepath.Dir(ex), "icevirtue.db")
			}
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
