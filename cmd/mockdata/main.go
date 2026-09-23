// Command mockdata creates a disposable database with representative dashboard data.
// It never talks to reconnaissance tools or external systems.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func main() {
	dbPath := flag.String("db-path", "mock-dashboard.db", "Disposable SQLite database to create")
	username := flag.String("username", "demo", "Dashboard username to seed")
	password := flag.String("password", "recon-demo", "Dashboard password to seed")
	reset := flag.Bool("reset", false, "Replace an existing fixture database at --db-path")
	flag.Parse()

	if err := prepareDatabase(*dbPath, *reset); err != nil {
		log.Fatal(err)
	}
	if err := database.InitDatabase(*dbPath); err != nil {
		log.Fatalf("initializing fixture database: %v", err)
	}
	if err := database.RunDataMigrations(); err != nil {
		log.Fatalf("migrating fixture database: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("hashing demo password: %v", err)
	}
	if err := database.DB.Create(&models.User{Username: *username, PasswordHash: string(hash)}).Error; err != nil {
		log.Fatalf("creating demo user: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	seedPrimaryProfile(now)
	seedSecondaryProfile(now)

	abs, err := filepath.Abs(*dbPath)
	if err != nil {
		abs = *dbPath
	}
	fmt.Printf("[+] Mock dashboard database created: %s\n", abs)
	fmt.Printf("[+] Sign in with username %q and password %q\n", *username, *password)
	fmt.Printf("[+] Start ICEvirtue with: ICEvirtue --db-path %q\n", abs)
}

func prepareDatabase(path string, reset bool) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("checking fixture database %q: %w", path, err)
	}
	if !reset {
		return fmt.Errorf("fixture database %q already exists; pass --reset to replace it", path)
	}

	// SQLite's WAL sidecars belong to this exact database. Remove them only after the
	// caller explicitly requested replacement of this named fixture path.
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Remove(candidate); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing fixture database %q: %w", candidate, err)
		}
	}
	return nil
}

func seedPrimaryProfile(now time.Time) {
	profile := createProfile("acme.example.com", "full", "every day at 09:00")

	app := createAsset(profile, "app.acme.example.com", now.AddDate(0, 0, -45), now.AddDate(0, 0, -1), now)
	api := createAsset(profile, "api.acme.example.com", now.AddDate(0, 0, -30), now.AddDate(0, 0, -4), now)
	admin := createAsset(profile, "admin.acme.example.com", now.AddDate(0, 0, -20), now.Add(-7*24*time.Hour), now)
	createAsset(profile, "legacy.acme.example.com", now.AddDate(0, 0, -70), now.AddDate(0, 0, -70), now)
	createAsset(profile, "quiet.acme.example.com", now.AddDate(0, 0, -10), now.AddDate(0, 0, -10), now)
	createAsset(profile, "203.0.113.42", now.AddDate(0, 0, -12), now.AddDate(0, 0, -2), now)

	createHost(profile, "https://app.acme.example.com", "203.0.113.10", "Acme customer portal", "cloudflare", 200)
	createHost(profile, "https://api.acme.example.com", "203.0.113.11", "Acme API", "nginx", 403)
	createHost(profile, "https://admin.acme.example.com", "203.0.113.12", "Admin console", "nginx", 200)
	createHost(profile, "http://203.0.113.42", "203.0.113.42", "Legacy endpoint", "Apache", 301)

	createVulnerability(profile, app, "missing-hsts", "https://app.acme.example.com", "critical", "HSTS header missing", "The application does not set a Strict-Transport-Security header.")
	createVulnerability(profile, app, "exposed-git-config", "https://app.acme.example.com/.git/config", "high", "Exposed Git configuration", "A Git configuration file is publicly accessible.")
	createVulnerability(profile, app, "x-frame-options", "https://app.acme.example.com", "medium", "X-Frame-Options missing", "The portal can be embedded by another origin.")
	createVulnerability(profile, app, "tech-detect", "https://app.acme.example.com", "info", "Technology detected", "The host exposes identifiable framework metadata.")
	createVulnerability(profile, api, "swagger-ui", "https://api.acme.example.com/swagger", "low", "Swagger UI exposed", "An API documentation interface is available.")
	createVulnerability(profile, api, "tech-detect", "https://api.acme.example.com", "info", "Technology detected", "The host exposes identifiable framework metadata.")
	createVulnerability(profile, admin, "default-login", "https://admin.acme.example.com/login", "high", "Default login page", "An administrative login surface was discovered.")

	createDirectory(profile, app, "https://app.acme.example.com", "https://app.acme.example.com/admin", 403)
	createDirectory(profile, app, "https://app.acme.example.com", "https://app.acme.example.com/backup.zip", 200)
	createDirectory(profile, api, "https://api.acme.example.com", "https://api.acme.example.com/v1", 200)
	createDirectory(profile, admin, "https://admin.acme.example.com", "https://admin.acme.example.com/debug", 405)

	createSecret(profile, app, "https://app.acme.example.com/static/app.9f4a.js", "aws-access-key", "AKIAIOSFODNN7EXAMPLE")
	createSecret(profile, api, "https://api.acme.example.com/openapi.json", "generic-api-key", "demo-api-key-7d2d")
}

func seedSecondaryProfile(now time.Time) {
	profile := createProfile("globex.example.net", "passive", "every week at 10:00")
	portal := createAsset(profile, "portal.globex.example.net", now.AddDate(0, 0, -15), now.AddDate(0, 0, -3), now)
	createAsset(profile, "assets.globex.example.net", now.AddDate(0, 0, -15), now.AddDate(0, 0, -15), now)
	createHost(profile, "https://portal.globex.example.net", "198.51.100.20", "Globex partner portal", "Caddy", 200)
	createVulnerability(profile, portal, "cors-misconfig", "https://portal.globex.example.net/api", "medium", "Permissive CORS policy", "The API accepts an untrusted origin.")
	createDirectory(profile, portal, "https://portal.globex.example.net", "https://portal.globex.example.net/health", 200)
}

func createProfile(domain, mode, schedule string) models.Profile {
	profile := models.Profile{Domain: domain, Mode: mode, Schedule: schedule, Enabled: true}
	if err := database.DB.Create(&profile).Error; err != nil {
		log.Fatalf("creating profile %s: %v", domain, err)
	}
	return profile
}

func createAsset(profile models.Profile, domain string, firstSeen, lastChanged, lastSeen time.Time) string {
	row := models.Subdomain{ProfileID: profile.ID, Domain: domain, FirstSeen: firstSeen, LastChanged: lastChanged, LastSeen: lastSeen}
	if err := database.DB.Create(&row).Error; err != nil {
		log.Fatalf("creating asset %s: %v", domain, err)
	}
	return domain
}

func createHost(profile models.Profile, url, ip, title, webServer string, status int) {
	if err := database.DB.Create(&models.AliveHost{ProfileID: profile.ID, URL: url, IP: ip, Title: title, WebServer: webServer, StatusCode: status}).Error; err != nil {
		log.Fatalf("creating host %s: %v", url, err)
	}
}

func createVulnerability(profile models.Profile, host, templateID, url, severity, name, description string) {
	if err := database.DB.Create(&models.Vulnerability{ProfileID: profile.ID, TemplateID: templateID, URL: url, Severity: severity, Name: name, Description: description}).Error; err != nil {
		log.Fatalf("creating vulnerability for %s: %v", host, err)
	}
}

func createDirectory(profile models.Profile, host, subdomainURL, dirURL string, status int) {
	if err := database.DB.Create(&models.DirectoryFinding{ProfileID: profile.ID, SubdomainURL: subdomainURL, DirURL: dirURL, StatusCode: status}).Error; err != nil {
		log.Fatalf("creating directory for %s: %v", host, err)
	}
}

func createSecret(profile models.Profile, host, sourceURL, secretType, secretValue string) {
	if err := database.DB.Create(&models.SecretFinding{ProfileID: profile.ID, SourceURL: sourceURL, SecretType: secretType, SecretValue: secretValue}).Error; err != nil {
		log.Fatalf("creating secret for %s: %v", host, err)
	}
}
