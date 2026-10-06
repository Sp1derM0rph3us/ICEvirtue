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
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	dbPath := flag.String("db-path", "mock-dashboard.db", "Disposable SQLite database to create")
	username := flag.String("username", "demo", "Dashboard username to seed")
	password := flag.String("password", "recon-demo", "Dashboard password to seed")
	reset := flag.Bool("reset", false, "Replace an existing fixture database at --db-path")
	flag.Parse()

	if err := prepareDatabase(*dbPath, *reset); err != nil {
		return err
	}
	store, err := database.Open(*dbPath, true)
	if err != nil {
		return err
	}
	defer store.Close()
	fixture := &fixture{store: store}

	hash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing demo password: %w", err)
	}
	if err := store.DB.Create(&models.User{Username: *username, PasswordHash: string(hash), Role: "admin"}).Error; err != nil {
		return fmt.Errorf("creating demo user: %w", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	fixture.seedPrimaryProfile(now)
	fixture.seedSecondaryProfile(now)
	if fixture.err != nil {
		return fixture.err
	}

	abs, err := filepath.Abs(*dbPath)
	if err != nil {
		abs = *dbPath
	}
	fmt.Printf("[+] Mock dashboard database created: %s\n", abs)
	fmt.Printf("[+] Sign in with username %q and password %q\n", *username, *password)
	fmt.Printf("[+] Start ICEvirtue with: ICEvirtue --db-path %q\n", abs)
	return nil
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

func (f *fixture) seedPrimaryProfile(now time.Time) {
	profile := f.createProfile("acme.example.com", "full", "every day at 09:00")

	app := f.createAsset(profile, "app.acme.example.com", now.AddDate(0, 0, -45), now.AddDate(0, 0, -1), now)
	api := f.createAsset(profile, "api.acme.example.com", now.AddDate(0, 0, -30), now.AddDate(0, 0, -4), now)
	auth := f.createAsset(profile, "auth.acme.example.com", now.AddDate(0, 0, -5), now.AddDate(0, 0, -1), now)
	admin := f.createAsset(profile, "admin.acme.example.com", now.AddDate(0, 0, -20), now.Add(-7*24*time.Hour), now)
	f.createAsset(profile, "legacy.acme.example.com", now.AddDate(0, 0, -70), now.AddDate(0, 0, -70), now)
	f.createAsset(profile, "quiet.acme.example.com", now.AddDate(0, 0, -10), now.AddDate(0, 0, -10), now)
	f.createAsset(profile, "203.0.113.42", now.AddDate(0, 0, -12), now.AddDate(0, 0, -2), now)

	f.createHost(profile, "https://app.acme.example.com", "203.0.113.10", "Acme customer portal", "cloudflare", 200, "Cloudflare")
	// Same product on a second endpoint exercises Home's one-entry-per-WAF list
	// and the node detail's aggregation across HTTP and HTTPS.
	f.createHost(profile, "http://app.acme.example.com", "203.0.113.10", "Acme customer portal", "cloudflare", 301, "Cloudflare")
	f.createHost(profile, "https://api.acme.example.com", "203.0.113.11", "Acme API", "nginx", 403, "Unknown WAF")
	f.createHost(profile, "https://admin.acme.example.com", "203.0.113.12", "Admin console", "nginx", 200, "none")
	f.createHost(profile, "https://auth.acme.example.com", "203.0.113.13", "Acme sign-in redirect", "nginx", 302, "none")
	f.createHost(profile, "http://203.0.113.42", "203.0.113.42", "Legacy endpoint", "Apache", 301, "none")

	f.createVulnerability(profile, app, "missing-hsts", "https://app.acme.example.com", "critical", "HSTS header missing", "The application does not set a Strict-Transport-Security header.")
	f.createVulnerability(profile, app, "exposed-git-config", "https://app.acme.example.com/.git/config", "high", "Exposed Git configuration", "A Git configuration file is publicly accessible.")
	f.createVulnerability(profile, app, "x-frame-options", "https://app.acme.example.com", "medium", "X-Frame-Options missing", "The portal can be embedded by another origin.")
	f.createVulnerability(profile, app, "tech-detect", "https://app.acme.example.com", "info", "Technology detected", "The host exposes identifiable framework metadata.")
	f.createVulnerability(profile, api, "swagger-ui", "https://api.acme.example.com/swagger", "low", "Swagger UI exposed", "An API documentation interface is available.")
	f.createVulnerability(profile, api, "tech-detect", "https://api.acme.example.com", "info", "Technology detected", "The host exposes identifiable framework metadata.")
	f.createVulnerability(profile, admin, "default-login", "https://admin.acme.example.com/login", "high", "Default login page", "An administrative login surface was discovered.")

	f.createDirectory(profile, app, "https://app.acme.example.com", "https://app.acme.example.com/admin", 403)
	f.createDirectory(profile, app, "https://app.acme.example.com", "https://app.acme.example.com/backup.zip", 200)
	f.createDirectory(profile, api, "https://api.acme.example.com", "https://api.acme.example.com/v1", 200)
	f.createDirectory(profile, admin, "https://admin.acme.example.com", "https://admin.acme.example.com/debug", 405)

	// Ambiguous paths remain available for review without inflating confirmed counts.
	f.createAssessedDirectory(profile, app, "https://app.acme.example.com", "https://app.acme.example.com/account", 200, "unknown", "matches_missing_paths")
	f.createAssessedDirectory(profile, api, "https://api.acme.example.com", "https://api.acme.example.com/private", 403, "unknown", "matches_missing_paths")
	f.createAssessedDirectory(profile, admin, "https://admin.acme.example.com", "https://admin.acme.example.com/internal", 405, "unknown", "baseline_unstable")
	f.createAssessedDirectory(profile, auth, "https://auth.acme.example.com", "https://auth.acme.example.com/reports", 302, "unknown", "matches_missing_paths")
	f.createAssessedDirectory(profile, app, "https://app.acme.example.com", "https://app.acme.example.com/old-export", 200, "legacy", "")

	// Each redirect is attributed to its source node. Destination enumeration is
	// independent of scope; preview.acme.example.com has not been enumerated.
	f.createAssessedDirectory(profile, app, "https://app.acme.example.com", "https://app.acme.example.com/admin-console", 301, "unknown", "cross_host")
	f.createAssessedDirectory(profile, app, "https://app.acme.example.com", "https://app.acme.example.com/preview", 307, "unknown", "cross_host")
	f.createAssessedDirectory(profile, admin, "https://admin.acme.example.com", "https://admin.acme.example.com/sso", 303, "unknown", "cross_scope")
	f.createRedirect(profile, app, "https://app.acme.example.com/admin-console", "https://admin.acme.example.com/login", "admin.acme.example.com", "cross_host", true, 301, now)
	f.createRedirect(profile, app, "https://app.acme.example.com/preview", "https://preview.acme.example.com/", "preview.acme.example.com", "cross_host", false, 307, now)
	f.createRedirect(profile, admin, "https://admin.acme.example.com/sso", "https://login.identity.example.net/authorize", "login.identity.example.net", "cross_scope", false, 303, now)
	// Root redirects exist even without a corresponding directory finding.
	f.createRedirect(profile, auth, "https://auth.acme.example.com", "https://login.identity.example.net/authorize", "login.identity.example.net", "cross_scope", false, 302, now)

	f.createSecret(profile, models.SecretFinding{
		SourceURL:   "https://app.acme.example.com/static/app.9f4a.js",
		SecretType:  "aws-access-key",
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
		Engine:      "SecretHound",
		Risk:        "high",
		Description: "AWS access key embedded in client JavaScript.",
		Context:     []string{"const awsAccessKeyId = 'AKIAIOSFODNN7EXAMPLE';", "window.appConfig.awsAccessKeyId = awsAccessKeyId;"},
		Occurrences: 2,
	})
	f.createSecret(profile, models.SecretFinding{
		SourceURL:   "https://api.acme.example.com/openapi.json",
		SecretType:  "generic-api-key",
		SecretValue: "demo-api-key-7d2d",
		Engine:      "SecretHound",
		Risk:        "medium",
		Description: "Example API key in the published API document.",
		Context:     []string{"x-api-key: demo-api-key-7d2d"},
		Occurrences: 1,
	})
	f.createSecret(profile, models.SecretFinding{
		SourceURL:   "mantra-discovery",
		SecretType:  "generic-token",
		SecretValue: "mock-mantra-token-42",
		Engine:      "Mantra",
	})
	// This overlap remains in the database but the Credentials API prefers the
	// sourced SecretHound row when both engines report the same credential.
	f.createSecret(profile, models.SecretFinding{
		SourceURL:   "mantra-discovery",
		SecretType:  "aws-access-key",
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
		Engine:      "Mantra",
	})
}

func (f *fixture) seedSecondaryProfile(now time.Time) {
	profile := f.createProfile("globex.example.net", "passive", "every week at 10:00")
	portal := f.createAsset(profile, "portal.globex.example.net", now.AddDate(0, 0, -15), now.AddDate(0, 0, -3), now)
	f.createAsset(profile, "assets.globex.example.net", now.AddDate(0, 0, -15), now.AddDate(0, 0, -15), now)
	f.createHost(profile, "https://portal.globex.example.net", "198.51.100.20", "Globex partner portal", "Caddy", 200, "Akamai")
	f.createVulnerability(profile, portal, "cors-misconfig", "https://portal.globex.example.net/api", "medium", "Permissive CORS policy", "The API accepts an untrusted origin.")
	f.createDirectory(profile, portal, "https://portal.globex.example.net", "https://portal.globex.example.net/health", 200)
}

func (f *fixture) createProfile(domain, mode, schedule string) models.Profile {
	profile := models.Profile{Domain: domain, Mode: mode, Schedule: schedule, Enabled: true}
	if err := f.create(&profile); err != nil {
		f.err = fmt.Errorf("creating profile %s: %v", domain, err)
	}
	return profile
}

func (f *fixture) createAsset(profile models.Profile, domain string, firstSeen, lastChanged, lastSeen time.Time) string {
	row := models.Subdomain{ProfileID: profile.ID, Domain: domain, FirstSeen: firstSeen, LastChanged: lastChanged, LastSeen: lastSeen}
	if err := f.create(&row); err != nil {
		f.err = fmt.Errorf("creating asset %s: %v", domain, err)
	}
	return domain
}

func (f *fixture) createHost(profile models.Profile, url, ip, title, webServer string, status int, waf string) {
	if err := f.create(&models.AliveHost{ProfileID: profile.ID, URL: url, IP: ip, Title: title, WebServer: webServer, StatusCode: status, WAFName: &waf}); err != nil {
		f.err = fmt.Errorf("creating host %s: %v", url, err)
	}
}

func (f *fixture) createVulnerability(profile models.Profile, host, templateID, url, severity, name, description string) {
	if err := f.create(&models.Vulnerability{ProfileID: profile.ID, TemplateID: templateID, URL: url, Severity: severity, Name: name, Description: description}); err != nil {
		f.err = fmt.Errorf("creating vulnerability for %s: %v", host, err)
	}
}

func (f *fixture) createDirectory(profile models.Profile, host, subdomainURL, dirURL string, status int) {
	f.createAssessedDirectory(profile, host, subdomainURL, dirURL, status, "confirmed", "distinct_from_missing_paths")
}

func (f *fixture) createAssessedDirectory(profile models.Profile, host, subdomainURL, dirURL string, status int, assessment, reason string) {
	if err := f.create(&models.DirectoryFinding{ProfileID: profile.ID, SubdomainURL: subdomainURL, DirURL: dirURL, StatusCode: status, Assessment: assessment, AssessmentReason: reason}); err != nil {
		f.err = fmt.Errorf("creating directory for %s: %v", host, err)
	}
}

func (f *fixture) createRedirect(profile models.Profile, host, sourceURL, destinationURL, destinationHost, kind string, enumerated bool, status int, observedAt time.Time) {
	if err := f.create(&models.RedirectObservation{ProfileID: profile.ID, Host: host, SourceURL: sourceURL, DestinationURL: destinationURL, DestinationHost: destinationHost, Kind: kind, PreviouslyEnumerated: enumerated, StatusCode: status, ObservedAt: observedAt}); err != nil {
		f.err = fmt.Errorf("creating redirect for %s: %v", host, err)
	}
}

func (f *fixture) createSecret(profile models.Profile, finding models.SecretFinding) {
	finding.ProfileID = profile.ID
	if err := f.create(&finding); err != nil {
		f.err = fmt.Errorf("creating secret from %s: %v", finding.SourceURL, err)
	}
}

type fixture struct {
	store *database.Store
	err   error
}

func (f *fixture) create(row any) error {
	if f.err != nil {
		return f.err
	}
	return f.store.DB.Create(row).Error
}
