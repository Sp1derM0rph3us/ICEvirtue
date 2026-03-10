package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/api"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/engine"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/scheduler"
)

func main() {
	flag.BoolVar(&engine.Verbose, "verbose", false, "Print detailed scan findings to the terminal")
	flag.StringVar(&engine.Wordlist, "wordlist", "", "Absolute path to wordlist for active dnsx bruteforcing (Full Mode only)")
	flag.BoolVar(&engine.SkipAmass, "skip-amass", false, "Skip Amass execution during subdomain enumeration (Full Mode only)")
	flag.BoolVar(&engine.SkipNuclei, "skip-nuclei", false, "Skip Nuclei execution during vulnerability scanning")
	
	var apiPort int
	flag.IntVar(&apiPort, "api-port", 8888, "Port for the web dashboard to listen on")
	flag.Parse()

	err := database.InitDatabase("icevirtue.db")
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
