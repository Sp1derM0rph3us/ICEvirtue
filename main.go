package main

import (
	"flag"
	"fmt"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/serverlogs"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/api"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/engine"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/scheduler"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/wordlists"
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

// validateListenIP rejects a listen address that is not an IP of the expected
// family, so an --ipv4/--ipv6 typo fails fast with a clear message rather than
// as an opaque bind error later.
func validateListenIP(value string, wantV6 bool) error {
	ip := net.ParseIP(value)
	if ip == nil {
		return fmt.Errorf("%q is not a valid IP address", value)
	}
	if gotV6 := ip.To4() == nil; gotV6 != wantV6 {
		if wantV6 {
			return fmt.Errorf("%q is not an IPv6 address", value)
		}
		return fmt.Errorf("%q is not an IPv4 address", value)
	}
	return nil
}

func main() {
	log.SetOutput(io.MultiWriter(os.Stderr, serverlogs.Default))
	flag.StringVar(&engine.ToolHome, "tool-home", "", "Directory the external tools use for their config (default /opt/icevirtue, falling back to $HOME)")
	flag.StringVar(&engine.ToolPaths, "tool-paths", "", "Comma-separated name=path overrides for external tools (e.g. httpx=/usr/bin/httpx-toolkit)")
	flag.StringVar(&engine.WaymoreConfig, "waymore-config", "", "Optional Waymore config.yml containing provider API keys and filters")

	var apiPort int
	var uploadDir string
	flag.StringVar(&uploadDir, "upload-dir", "uploads", "Private wordlist storage directory (default uploads under the service working directory)")
	var dbPath string
	var jwtSecretPath string
	var webDir string
	var secureCookies bool
	var sessionTTL time.Duration
	var trustedOrigins originList
	var reloadTemplates bool
	var ipv4Addr, ipv6Addr string
	flag.IntVar(&apiPort, "api-port", 8888, "Port for the web dashboard to listen on")
	flag.StringVar(&ipv4Addr, "ipv4", "127.0.0.1",
		"IPv4 address the dashboard listens on. Defaults to loopback (localhost only); pass 0.0.0.0 for all IPv4 interfaces, or a specific interface address.")
	flag.StringVar(&ipv6Addr, "ipv6", "::1",
		"IPv6 address the dashboard listens on. Defaults to loopback (localhost only); pass :: for all IPv6 interfaces, or a specific interface address.")
	flag.StringVar(&dbPath, "db-path", "icevirtue.db", "Path to the database file (must match the path used by ICEvirtue-admin)")
	flag.StringVar(&jwtSecretPath, "jwt-secret", "", "Path to the JWT signing key (default /var/lib/icevirtue/jwt.secret, falling back to $XDG_STATE_HOME/icevirtue)")
	flag.StringVar(&webDir, "web-dir", "web", "Directory holding the dashboard's templates/ and static/ folders")
	flag.BoolVar(&secureCookies, "secure-cookies", false,
		"Mark the session cookie Secure. Turn this on whenever the dashboard is reached over HTTPS, including behind a TLS-terminating proxy. Leaving it off over plain HTTP is required, because a browser accepts a Secure cookie and then never sends it back.")
	flag.DurationVar(&sessionTTL, "session-ttl", auth.DefaultSessionTTL, "How long a dashboard session lasts before it has to be re-established")
	flag.Var(&trustedOrigins, "trusted-origin",
		"An Origin to accept on state-changing requests in addition to the request's own host. Repeatable. Needed when a reverse proxy rewrites Host, because otherwise every write is refused with 403.")
	flag.BoolVar(&reloadTemplates, "reload-templates", false,
		"Re-read the HTML templates from disk on every request so template edits appear on refresh without a restart. Development only; leave off in production.")
	flag.Parse()
	if sessionTTL < time.Second || sessionTTL > auth.MaxSessionTTL {
		log.Fatal("[-] Session TTL must be between one second and seven days")
	}
	if err := validateListenIP(ipv4Addr, false); err != nil {
		log.Fatalf("[-] --ipv4: %v", err)
	}
	if err := validateListenIP(ipv6Addr, true); err != nil {
		log.Fatalf("[-] --ipv6: %v", err)
	}

	if err := auth.Init(jwtSecretPath); err != nil {
		log.Fatalf("[-] %v", err)
	}

	unlock, err := database.LockServer(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer unlock()
	err = database.InitDatabase(dbPath)
	if err != nil {
		log.Fatalf("[-] Failed to initialize database: %v", err)
	}

	// Before the scheduler and the server start, so nothing competes for the single
	// database connection and no request can observe a half-backfilled state.
	if err := database.RunDataMigrations(); err != nil {
		log.Fatalf("[-] Failed to migrate existing data: %v", err)
	}

	store, err := wordlists.New(database.DB, uploadDir, webDir)
	if err != nil {
		log.Fatalf("[-] Upload storage: %v", err)
	}
	defer store.Close()
	if err = store.Reconcile(); err != nil {
		log.Fatalf("[-] Upload recovery: %v", err)
	}
	configuration, err := appconfig.Load(database.DB)
	if err != nil {
		log.Fatal(err)
	}
	engine.PreflightTools(configuration)
	coordinator := engine.NewCoordinator(database.DB, store)
	if err = coordinator.Recover(); err != nil {
		log.Fatal(err)
	}
	coordinator.Start()

	sched := scheduler.NewScheduler(coordinator)
	if err := sched.Start(); err != nil {
		log.Fatalf("[-] Failed to start scheduler: %v", err)
	}

	if !secureCookies {
		log.Printf("[!] The session cookie is not marked Secure, so anything on the network path can read it. Pass --secure-cookies when the dashboard is served over HTTPS.")
	}

	cfg := api.Config{
		Wordlists: store,
		// Templates live outside the tree served under /static. Serving the whole web
		// folder meant GET /static/template.html handed the entire authenticated
		// dashboard to anyone, and GET /static/ listed the directory.
		Templates:       api.DirFS(filepath.Join(webDir, "templates")),
		Static:          api.DirFS(filepath.Join(webDir, "static")),
		SecureCookies:   secureCookies,
		TrustedOrigins:  trustedOrigins,
		SessionTTL:      sessionTTL,
		ReloadTemplates: reloadTemplates,
	}

	// Surface a bind failure or a broken template as a normal fatal, rather than as a
	// log.Fatalf from inside a goroutine nobody is watching.
	serverErr := make(chan error, 1)
	go func() { serverErr <- api.StartServer(ipv4Addr, ipv6Addr, apiPort, sched, cfg) }()

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
	coordinator.Stop()

	log.Println("[+] Shutdown complete. Goodbye.")
}
