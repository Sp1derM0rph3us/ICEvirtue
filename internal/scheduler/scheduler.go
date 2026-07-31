package scheduler

import (
	"fmt"
	"log"
	"sync"

	"github.com/robfig/cron/v3"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/engine"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type Scheduler struct {
	// mu serialises rebuild.
	//
	// cron.Cron's own Entries, Remove and AddFunc are each goroutine-safe, but the
	// compound remove-everything-then-add-everything is not: two API calls landing
	// together could both remove and both add, leaving a profile scheduled twice and
	// therefore scanned twice per interval. Sync is reachable from three HTTP handlers,
	// so that race was live.
	mu   sync.Mutex
	Cron *cron.Cron
}

func NewScheduler() *Scheduler {
	return &Scheduler{Cron: cron.New(cron.WithSeconds())}
}

// Start builds the schedule and then starts the cron loop.
//
// It shares rebuild with Sync. The two used to carry copies of the same twenty-line
// loop, which is how they would eventually have drifted.
func (s *Scheduler) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.rebuild(); err != nil {
		return err
	}

	s.Cron.Start()
	log.Println("[+] Scheduler running in background")
	return nil
}

func (s *Scheduler) Stop() {
	s.Cron.Stop()
	log.Println("[*] Scheduler stopped")
}

// Sync reloads the schedule from the database.
func (s *Scheduler) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Println("[*] Synchronizing Scheduler with Database Profiles...")
	return s.rebuild()
}

// rebuild replaces the whole schedule. The caller must hold mu.
func (s *Scheduler) rebuild() error {
	// Read before removing.
	//
	// This used to remove every entry first and only then query. A failed read
	// therefore returned an error with nothing scheduled at all — a silent, total
	// outage of scheduled scanning — and all three callers discarded that error.
	var profiles []models.Profile
	if err := database.DB.Where("enabled = ?", true).Find(&profiles).Error; err != nil {
		return fmt.Errorf("loading profiles to schedule: %w", err)
	}

	for _, entry := range s.Cron.Entries() {
		s.Cron.Remove(entry.ID)
	}

	log.Printf("[*] Found %d active profiles. Setting up schedules...", len(profiles))

	for _, p := range profiles {
		profile := p

		cronExpr, err := ParseSchedule(profile.Schedule)
		if err != nil {
			log.Printf("[-] Failed to parse schedule for profile %s: %v", profile.Domain, err)
			continue
		}

		// &profile is captured for the life of the entry, but OrchestrateScan reloads the
		// row before it does anything with it, so a stale copy here is harmless. Do not
		// "fix" this by re-querying at fire time: the reload is the fix.
		_, err = s.Cron.AddFunc(cronExpr, func() {
			log.Printf("[*] [Target: %s] Triggering scheduled scan mode: %s", profile.Domain, profile.Mode)
			engine.OrchestrateScan(&profile)
		})
		if err != nil {
			log.Printf("[-] Failed to schedule profile %s: %v", profile.Domain, err)
			continue
		}

		log.Printf("[+] Scheduled %s with interval: %s (Parsed: %s)", profile.Domain, profile.Schedule, cronExpr)
	}

	return nil
}
