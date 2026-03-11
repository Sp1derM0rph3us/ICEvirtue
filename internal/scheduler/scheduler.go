package scheduler

import (
	"log"
	
	"github.com/robfig/cron/v3"
	
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/engine"
)

type Scheduler struct {
	Cron *cron.Cron
}

func NewScheduler() *Scheduler {
	c := cron.New(cron.WithSeconds())
	return &Scheduler{
		Cron: c,
	}
}

func (s *Scheduler) Start() error {
	var profiles []models.Profile
	
	if err := database.DB.Where("enabled = ?", true).Find(&profiles).Error; err != nil {
		return err
	}
	
	log.Printf("[*] Found %d active profiles. Setting up schedules...", len(profiles))

	for _, p := range profiles {
		profile := p
		
		cronExpr, err := ParseSchedule(profile.Schedule)
		if err != nil {
			log.Printf("[-] Failed to parse schedule for profile %s: %v", profile.Domain, err)
			continue
		}

		_, err = s.Cron.AddFunc(cronExpr, func() {
			log.Printf("[*] [Target: %s] Triggering scheduled scan mode: %s", profile.Domain, profile.Mode)
			engine.OrchestrateScan(&profile)
		})
		
		if err != nil {
			log.Printf("[-] Failed to schedule profile %s: %v", profile.Domain, err)
		} else {
			log.Printf("[+] Scheduled %s with interval: %s (Parsed: %s)", profile.Domain, profile.Schedule, cronExpr)
		}
	}
	
	s.Cron.Start()
	log.Println("[+] Scheduler running in background")
	
	return nil
}

func (s *Scheduler) Stop() {
	s.Cron.Stop()
	log.Println("[*] Scheduler stopped")
}

func (s *Scheduler) Sync() error {
	log.Println("[*] Synchronizing Scheduler with Database Profiles...")
	
	for _, entry := range s.Cron.Entries() {
		s.Cron.Remove(entry.ID)
	}

	var profiles []models.Profile
	if err := database.DB.Where("enabled = ?", true).Find(&profiles).Error; err != nil {
		return err
	}
	
	log.Printf("[*] Found %d active profiles for sync.", len(profiles))

	for _, p := range profiles {
		profile := p

		cronExpr, err := ParseSchedule(profile.Schedule)
		if err != nil {
			log.Printf("[-] Failed to parse schedule for sync on profile %s: %v", profile.Domain, err)
			continue
		}

		_, err = s.Cron.AddFunc(cronExpr, func() {
			log.Printf("[*] [Target: %s] Triggering scheduled scan mode: %s", profile.Domain, profile.Mode)
			engine.OrchestrateScan(&profile)
		})
		
		if err != nil {
			log.Printf("[-] Failed to schedule profile %s: %v", profile.Domain, err)
		} else {
			log.Printf("[+] Synchronized schedule for %s with interval: %s (Parsed: %s)", profile.Domain, profile.Schedule, cronExpr)
		}
	}

	return nil
}
