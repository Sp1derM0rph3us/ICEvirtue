package scheduler

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// newSchedulerEnv gives the test an isolated database seeded with enabled profiles.
func newSchedulerEnv(t *testing.T, domains ...string) *Scheduler {
	t.Helper()

	prevDB := database.DB
	t.Cleanup(func() { database.DB = prevDB })

	if err := database.InitDatabase(filepath.Join(t.TempDir(), "sched.db")); err != nil {
		t.Fatalf("InitDatabase: %v", err)
	}
	for _, d := range domains {
		if err := database.DB.Create(&models.Profile{
			Domain: d, Schedule: "every day at 03:00", Mode: "full", Enabled: true,
		}).Error; err != nil {
			t.Fatalf("seeding %s: %v", d, err)
		}
	}
	return NewScheduler()
}

// TestConcurrentSyncSchedulesEachProfileOnce asserts that concurrent syncs converge on
// one entry per profile.
//
// Be clear about what this does and does not prove. It passes with the mutex removed,
// because database.SetMaxOpenConns(1) serialises the query inside rebuild and so
// serialises most of it by accident. The mutex is still correct — cron's Entries, Remove
// and AddFunc are each goroutine-safe but the compound remove-then-add is not, and the
// single connection is a pool setting rather than a guarantee — so this is a guard
// against the day that setting changes, not a demonstration of a currently reachable
// bug. TestSyncLeavesTheScheduleIntactWhenTheReadFails is the one that fails against the
// previous code.
func TestConcurrentSyncSchedulesEachProfileOnce(t *testing.T) {
	s := newSchedulerEnv(t, "a.example.com", "b.example.com", "c.example.com")

	const callers = 25
	var release sync.WaitGroup
	var done sync.WaitGroup
	release.Add(1)

	for range callers {
		done.Add(1)
		go func() {
			defer done.Done()
			release.Wait()
			if err := s.Sync(); err != nil {
				t.Errorf("Sync: %v", err)
			}
		}()
	}

	release.Done()
	done.Wait()

	if got := len(s.Cron.Entries()); got != 3 {
		t.Errorf("%d concurrent syncs left %d cron entries, want 3 — a profile is scheduled more than once", callers, got)
	}
}

// TestSyncLeavesTheScheduleIntactWhenTheReadFails covers the read-before-remove order.
// Removing first meant a failed query returned an error having already emptied the
// schedule, so scheduled scanning stopped entirely and the caller discarded the error.
func TestSyncLeavesTheScheduleIntactWhenTheReadFails(t *testing.T) {
	s := newSchedulerEnv(t, "a.example.com", "b.example.com")

	if err := s.Sync(); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	before := len(s.Cron.Entries())
	if before != 2 {
		t.Fatalf("setup produced %d entries, want 2", before)
	}

	// Close the pool so the next read cannot succeed.
	sqlDB, err := database.DB.DB()
	if err != nil {
		t.Fatalf("getting the sql handle: %v", err)
	}
	sqlDB.Close()

	if err := s.Sync(); err == nil {
		t.Error("Sync reported success against a closed database")
	}
	if got := len(s.Cron.Entries()); got != before {
		t.Errorf("a failed Sync left %d entries, want the previous %d: scheduled scanning stopped silently", got, before)
	}
}

// TestSyncSkipsAnUnparseableSchedule checks one bad row does not cost the others their
// schedule.
func TestSyncSkipsAnUnparseableSchedule(t *testing.T) {
	s := newSchedulerEnv(t, "good.example.com")

	if err := database.DB.Create(&models.Profile{
		Domain: "bad.example.com", Schedule: "whenever I feel like it", Mode: "full", Enabled: true,
	}).Error; err != nil {
		t.Fatalf("seeding the bad profile: %v", err)
	}

	if err := s.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got := len(s.Cron.Entries()); got != 1 {
		t.Errorf("got %d entries, want 1: the good profile must still be scheduled", got)
	}
}

// TestStartAndSyncProduceTheSameSchedule guards the shared rebuild. The two used to be
// duplicated bodies, so they could drift.
func TestStartAndSyncProduceTheSameSchedule(t *testing.T) {
	s := newSchedulerEnv(t, "a.example.com", "b.example.com")

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(s.Stop)
	afterStart := len(s.Cron.Entries())

	if err := s.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if afterSync := len(s.Cron.Entries()); afterSync != afterStart {
		t.Errorf("Start scheduled %d entries but Sync scheduled %d", afterStart, afterSync)
	}
}
