package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/api"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/engine"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/scheduler"
)

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
	flag.IntVar(&apiPort, "api-port", 8888, "Port for the web dashboard to listen on")
	flag.StringVar(&dbPath, "db-path", "icevirtue.db", "Path to the database file (must match the path used by ICEvirtue-admin)")
	flag.StringVar(&jwtSecretPath, "jwt-secret", "", "Path to the JWT signing key (default /var/lib/icevirtue/jwt.secret, falling back to $XDG_STATE_HOME/icevirtue)")
	flag.Parse()

	engine.PreflightTools()

	if err := auth.Init(jwtSecretPath); err != nil {
		log.Fatalf("[-] %v", err)
	}

	err := database.InitDatabase(dbPath)
	if err != nil {
		log.Fatalf("[-] Failed to initialize database: %v", err)
	}

	database.DB.Model(&models.Profile{}).Where("is_scanning = ?", true).Update("is_scanning", false)

	sched := scheduler.NewScheduler()
	if err := sched.Start(); err != nil {
		log.Fatalf("[-] Failed to start scheduler: %v", err)
	}

	go api.StartServer(apiPort, sched)

	log.Println("[+] ICEvirtue Engine is Online. Press Ctrl+C to exit.")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("\n[*] Shutting down...")
	sched.Stop()

	log.Println("[*] Releasing any active scan locks...")
	database.DB.Model(&models.Profile{}).Where("is_scanning = ?", true).Update("is_scanning", false)

	log.Println("[+] Shutdown complete. Goodbye.")
}
