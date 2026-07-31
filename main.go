package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/api"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/engine"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/scheduler"
)

// originList collects a repeatable --trusted-origin flag.
type originList []string

func (o *originList) String() string { return strings.Join(*o, ",") }

func (o *originList) Set(value string) error {
	if value = strings.TrimSpace(value); value != "" {
		*o = append(*o, value)
	}
	return nil
}

func main() {
	flag.BoolVar(&engine.Verbose, "verbose", false, "Print detailed scan findings to the terminal")
	flag.StringVar(&engine.DnsxList, "dnsx-list", "", "Comma-separated absolute paths to wordlists for active dnsx bruteforcing (Full Mode only)")
	flag.StringVar(&engine.DirectoryList, "directory-list", "", "Comma-separated absolute paths to wordlists for directory fuzzing")
	flag.BoolVar(&engine.SkipAmass, "skip-amass", false, "Skip Amass execution during subdomain enumeration (Full Mode only)")
	flag.BoolVar(&engine.SkipNuclei, "skip-nuclei", false, "Skip Nuclei execution during vulnerability scanning")
	flag.BoolVar(&engine.WideTargets, "wide-targets", false, "Feed every host that answered HTTP except 404s into fuzzing, Nuclei and secret hunting, instead of only 200/301/302/307")
	flag.StringVar(&engine.ToolHome, "tool-home", "", "Directory the external tools use for their config (default /opt/icevirtue, falling back to $HOME)")
	flag.StringVar(&engine.ToolPaths, "tool-paths", "", "Comma-separated name=path overrides for external tools (e.g. httpx=/usr/bin/httpx-toolkit)")

	var apiPort int
	var dbPath string
	var jwtSecretPath string
	var webDir string
	var secureCookies bool
	var sessionTTL time.Duration
	var trustedOrigins originList
	flag.IntVar(&apiPort, "api-port", 8888, "Port for the web dashboard to listen on")
	flag.StringVar(&dbPath, "db-path", "icevirtue.db", "Path to the database file (must match the path used by ICEvirtue-admin)")
	flag.StringVar(&jwtSecretPath, "jwt-secret", "", "Path to the JWT signing key (default /var/lib/icevirtue/jwt.secret, falling back to $XDG_STATE_HOME/icevirtue)")
	flag.StringVar(&webDir, "web-dir", "web", "Directory holding the dashboard's templates/ and static/ folders")
	flag.BoolVar(&secureCookies, "secure-cookies", false,
		"Mark the session cookie Secure. Turn this on whenever the dashboard is reached over HTTPS, including behind a TLS-terminating proxy. Leaving it off over plain HTTP is required, because a browser accepts a Secure cookie and then never sends it back.")
	flag.DurationVar(&sessionTTL, "session-ttl", auth.DefaultSessionTTL, "How long a dashboard session lasts before it has to be re-established")
	flag.Var(&trustedOrigins, "trusted-origin",
		"An Origin to accept on state-changing requests in addition to the request's own host. Repeatable. Needed when a reverse proxy rewrites Host, because otherwise every write is refused with 403.")
	flag.Parse()

	engine.PreflightTools()

	if err := auth.Init(jwtSecretPath); err != nil {
		log.Fatalf("[-] %v", err)
	}

	err := database.InitDatabase(dbPath)
	if err != nil {
		log.Fatalf("[-] Failed to initialize database: %v", err)
	}

	// Before the scheduler and the server start, so nothing competes for the single
	// database connection and no request can observe a half-backfilled state.
	if err := database.RunDataMigrations(); err != nil {
		log.Fatalf("[-] Failed to migrate existing data: %v", err)
	}

	database.DB.Model(&models.Profile{}).Where("is_scanning = ?", true).Update("is_scanning", false)

	sched := scheduler.NewScheduler()
	if err := sched.Start(); err != nil {
		log.Fatalf("[-] Failed to start scheduler: %v", err)
	}

	if !secureCookies {
		log.Printf("[!] The session cookie is not marked Secure, so anything on the network path can read it. Pass --secure-cookies when the dashboard is served over HTTPS.")
	}

	cfg := api.Config{
		// Templates live outside the tree served under /static. Serving the whole web
		// folder meant GET /static/template.html handed the entire authenticated
		// dashboard to anyone, and GET /static/ listed the directory.
		Templates:      api.DirFS(filepath.Join(webDir, "templates")),
		Static:         api.DirFS(filepath.Join(webDir, "static")),
		SecureCookies:  secureCookies,
		TrustedOrigins: trustedOrigins,
		SessionTTL:     sessionTTL,
	}

	// Surface a bind failure or a broken template as a normal fatal, rather than as a
	// log.Fatalf from inside a goroutine nobody is watching.
	serverErr := make(chan error, 1)
	go func() { serverErr <- api.StartServer(apiPort, sched, cfg) }()

	log.Println("[+] ICEvirtue Engine is Online. Press Ctrl+C to exit.")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		log.Fatalf("[-] Web server failed: %v", err)
	case <-sigChan:
	}

	log.Println("\n[*] Shutting down...")
	sched.Stop()

	log.Println("[*] Releasing any active scan locks...")
	database.DB.Model(&models.Profile{}).Where("is_scanning = ?", true).Update("is_scanning", false)

	log.Println("[+] Shutdown complete. Goodbye.")
}
