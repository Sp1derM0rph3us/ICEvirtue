// Package scheduler runs future schedules only while holding the database leader lease.
package scheduler

import (
	"context"
	"encoding/json"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/jobs"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
	"log"
	"sync"
	"time"
)

type Scheduler struct {
	db           *gorm.DB
	queue        *jobs.Queue
	owner, token string
	mu           sync.Mutex
	Cron         *cron.Cron
	fingerprint  string
	leader       bool
}

func New(db *gorm.DB, owner string) *Scheduler {
	return &Scheduler{db: db, queue: &jobs.Queue{DB: db}, owner: owner, token: uuid.NewString()}
}
func (s *Scheduler) Run(ctx context.Context) error {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	defer s.Stop()
	for {
		if e := s.Sync(); e != nil {
			log.Printf("scheduler: %v", e)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
func (s *Scheduler) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var e error
	if s.leader {
		var ok bool
		ok, e = s.queue.RenewLeader(s.owner, s.token)
		if e != nil {
			return e
		} // Keep the last schedule; its callbacks remain fenced.
		if !ok {
			if s.Cron != nil {
				s.Cron.Stop()
				s.Cron = nil
			}
			s.leader = false
		}
	}
	if !s.leader {
		token := uuid.NewString()
		ok, err := s.queue.Lead(s.owner, token)
		if err != nil || !ok {
			return err
		}
		s.token = token
		s.leader = true
		s.fingerprint = ""
	}
	var profiles []models.Profile
	if e = s.db.Where("enabled=?", true).Order("id").Find(&profiles).Error; e != nil {
		return e
	}
	// Only scheduling inputs affect the fingerprint; scan status changes do not rebuild cron.
	type entry struct{ ID, Domain, Schedule, Mode string }
	inputs := make([]entry, 0, len(profiles))
	for _, p := range profiles {
		inputs = append(inputs, entry{p.ID.String(), p.Domain, p.Schedule, p.Mode})
	}
	raw, _ := json.Marshal(inputs)
	fingerprint := string(raw)
	if s.leader && fingerprint == s.fingerprint {
		return nil
	}
	next := cron.New(cron.WithSeconds())
	for _, p := range profiles {
		id := p.ID.String()
		token := s.token
		expr, e := ParseSchedule(p.Schedule)
		if e != nil {
			return e
		}
		if _, e = next.AddFunc(expr, func() {
			if e := s.queue.EnqueueScheduled(id, "scheduled", token); e != nil && e != jobs.ErrDuplicate {
				log.Printf("scheduled admission: %v", e)
			}
		}); e != nil {
			return e
		}
	}
	old := s.Cron
	s.Cron = next
	s.fingerprint = fingerprint
	s.leader = true
	if old != nil {
		old.Stop()
	}
	next.Start()
	return nil
}
func (s *Scheduler) Start() error { return s.Sync() }
func (s *Scheduler) Stop() {
	s.mu.Lock()
	old := s.Cron
	s.Cron = nil
	s.leader = false
	s.mu.Unlock()
	if old != nil {
		<-old.Stop().Done()
	}
	s.queue.ReleaseLeader(s.owner, s.token)
}
