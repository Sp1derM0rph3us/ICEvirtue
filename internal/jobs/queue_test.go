package jobs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func queueEnv(t *testing.T) (*Queue, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shared.db")
	s, e := database.Open(path, true)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return &Queue{DB: s.DB}, path
}
func addProfile(t *testing.T, q *Queue) models.Profile {
	t.Helper()
	p := models.Profile{Domain: uuid.NewString() + ".test", Enabled: true}
	if e := q.DB.Create(&p).Error; e != nil {
		t.Fatal(e)
	}
	if e := q.Enqueue(p.ID.String(), "manual"); e != nil {
		t.Fatal(e)
	}
	return p
}

// Separate OS processes, connections and caches contend on the same WAL database.
func TestWorkerProcessHelper(t *testing.T) {
	path := os.Getenv("ICEVIRTUE_QUEUE_HELPER")
	if path == "" {
		return
	}
	s, e := database.Open(path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	q := &Queue{DB: s.DB}
	for i := 0; i < 500; i++ {
		c, e := q.Claim(fmt.Sprint(os.Getpid()))
		if e != nil {
			t.Fatal(e)
		}
		if c == nil {
			var queued int64
			q.DB.Model(&models.ScanJob{}).Where("state='queued'").Count(&queued)
			if queued == 0 {
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		var n int64
		if e = q.DB.Model(&models.ScanJob{}).Where("state='running'").Count(&n).Error; e != nil {
			t.Fatal(e)
		}
		if n > 2 {
			t.Fatalf("global concurrency exceeded: %d", n)
		}
		time.Sleep(20 * time.Millisecond)
		if e = q.Finish(c.Job, "completed", "completed"); e != nil {
			t.Fatal(e)
		}
	}
	t.Fatal("workers failed to drain queue")
}
func TestMultipleProcessesClaimExactlyOnceWithinGlobalLimit(t *testing.T) {
	q, path := queueEnv(t)
	for i := 0; i < 30; i++ {
		addProfile(t, q)
	}
	type child struct {
		cmd    *exec.Cmd
		output bytes.Buffer
	}
	children := make([]*child, 3)
	for i := range children {
		c := &child{}
		c.cmd = exec.Command(os.Args[0], "-test.run=^TestWorkerProcessHelper$", "-test.timeout=30s")
		c.cmd.Env = append(os.Environ(), "ICEVIRTUE_QUEUE_HELPER="+path)
		c.cmd.Stdout = &c.output
		c.cmd.Stderr = &c.output
		if e := c.cmd.Start(); e != nil {
			t.Fatal(e)
		}
		children[i] = c
	}
	for _, c := range children {
		if e := c.cmd.Wait(); e != nil {
			t.Fatalf("worker: %v\n%s", e, c.output.String())
		}
	}
	var runs, distinct, active int64
	q.DB.Model(&models.ScanRun{}).Count(&runs)
	q.DB.Model(&models.ScanRun{}).Distinct("profile_id").Count(&distinct)
	q.DB.Model(&models.ScanJob{}).Count(&active)
	if runs != 30 || distinct != 30 || active != 0 {
		t.Fatalf("runs=%d distinct=%d jobs=%d", runs, distinct, active)
	}
}
func TestExpiredLeaseFencesWritesAndRecoveryRetainsCommittedFindings(t *testing.T) {
	q, _ := queueEnv(t)
	p := addProfile(t, q)
	c, e := q.Claim("dead-worker")
	if e != nil || c == nil {
		t.Fatal(e)
	}
	if e = q.DB.Transaction(func(tx *gorm.DB) error {
		if e := Fence(tx, c.Job); e != nil {
			return e
		}
		return tx.Create(&models.Subdomain{ProfileID: p.ID, Domain: "committed.test"}).Error
	}); e != nil {
		t.Fatal(e)
	}
	q.DB.Create(&models.WordlistPin{JobID: c.Job.ID, WordlistID: uuid.NewString()})
	q.DB.Model(&models.ScanJob{}).Where("id=?", c.Job.ID).Update("lease_until", 0)
	if e = q.Renew(c.Job); !errors.Is(e, ErrLease) {
		t.Fatalf("renew=%v", e)
	}
	if e = q.DB.Transaction(func(tx *gorm.DB) error { return Fence(tx, c.Job) }); !errors.Is(e, ErrLease) {
		t.Fatalf("fence=%v", e)
	}
	if e = q.Finish(c.Job, "completed", "completed"); !errors.Is(e, ErrLease) {
		t.Fatalf("finish=%v", e)
	}
	if e = q.Reap(); e != nil {
		t.Fatal(e)
	}
	var run models.ScanRun
	q.DB.First(&run, "id=?", c.Job.RunID)
	if run.Status != "interrupted" || run.FinishedAt == nil {
		t.Fatalf("run=%+v", run)
	}
	for _, m := range []any{&models.ScanJob{}, &models.WordlistPin{}} {
		var n int64
		q.DB.Model(m).Count(&n)
		if n != 0 {
			t.Fatalf("recovery retained %T", m)
		}
	}
	var n int64
	q.DB.Model(&models.Subdomain{}).Count(&n)
	if n != 1 {
		t.Fatal("committed finding lost")
	}
	if c, e := q.Claim("replacement"); e != nil || c != nil {
		t.Fatalf("interrupted job retried: %+v %v", c, e)
	}
}
func TestLeaderTokenAndOldClaimCannotMutateNewOwnership(t *testing.T) {
	q, _ := queueEnv(t)
	ok, e := q.Lead("one", "token-one")
	if !ok || e != nil {
		t.Fatal(e)
	}
	if ok, e = q.Lead("two", "token-two"); ok || e != nil {
		t.Fatal("second leader elected")
	}
	p := models.Profile{Domain: "scheduled.test", Enabled: true}
	q.DB.Create(&p)
	if e = q.EnqueueScheduled(p.ID.String(), "scheduled", "token-two"); !errors.Is(e, ErrLease) {
		t.Fatal(e)
	}
	q.DB.Model(&models.SchedulerLease{}).Where("id=1").Update("lease_until", 0)
	if ok, e = q.Lead("two", "token-two"); !ok || e != nil {
		t.Fatal(e)
	}
	if e = q.EnqueueScheduled(p.ID.String(), "scheduled", "token-one"); !errors.Is(e, ErrLease) {
		t.Fatal(e)
	}
	if e = q.EnqueueScheduled(p.ID.String(), "scheduled", "token-two"); e != nil {
		t.Fatal(e)
	}
	c, e := q.Claim("worker")
	if e != nil {
		t.Fatal(e)
	}
	q.DB.Model(&models.ScanJob{}).Where("id=?", c.Job.ID).Update("token", "replacement")
	if e = q.Finish(c.Job, "completed", "completed"); !errors.Is(e, ErrLease) {
		t.Fatal(e)
	}
}
func TestRetentionAndOutboxTransaction(t *testing.T) {
	q, _ := queueEnv(t)
	old := time.Now().UTC().Add(-31 * 24 * time.Hour)
	q.DB.Create(&models.ScanRun{ID: "old", Status: "completed", FinishedAt: &old})
	q.DB.Create(&models.ScanRun{ID: "active", Status: "running", StartedAt: old})
	q.DB.Create(&models.ScanStageRun{RunID: "old"})
	q.DB.Create(&models.ScanToolRun{RunID: "old"})
	q.DB.Create(&models.OutboxEvent{Type: "expired", CreatedAt: old, Data: "null"})
	failure := errors.New("rollback")
	e := q.DB.Transaction(func(tx *gorm.DB) error {
		if e := events.Append(tx, "rolled-back", "", nil); e != nil {
			return e
		}
		return failure
	})
	if !errors.Is(e, failure) {
		t.Fatal(e)
	}
	if e = q.Prune(); e != nil {
		t.Fatal(e)
	}
	var runs []models.ScanRun
	q.DB.Find(&runs)
	if len(runs) != 1 || runs[0].ID != "active" {
		t.Fatal(runs)
	}
	for _, m := range []any{&models.OutboxEvent{}, &models.ScanStageRun{}, &models.ScanToolRun{}} {
		var n int64
		q.DB.Model(m).Count(&n)
		if n != 0 {
			t.Fatalf("retention retained %T", m)
		}
	}
}

func TestProfileFlagsClearWhenReloadingAfterCompletion(t *testing.T) {
	q, _ := queueEnv(t)
	p := addProfile(t, q)
	if e := q.DB.First(&p, "id=?", p.ID).Error; e != nil {
		t.Fatal(e)
	}
	if !p.IsQueued {
		t.Fatal("queued state missing")
	}
	c, e := q.Claim("worker")
	if e != nil {
		t.Fatal(e)
	}
	if e = q.Finish(c.Job, "completed", "completed"); e != nil {
		t.Fatal(e)
	}
	if e = q.DB.First(&p, "id=?", p.ID).Error; e != nil {
		t.Fatal(e)
	}
	if p.IsQueued || p.IsScanning {
		t.Fatal("reloaded profile retained stale state")
	}
}
func TestUnavailableWordlistFailsJobWithoutBlockingQueue(t *testing.T) {
	q, _ := queueEnv(t)
	p := addProfile(t, q)
	next := addProfile(t, q)
	config, e := appconfig.Load(q.DB)
	if e != nil {
		t.Fatal(e)
	}
	config.Scan.SkipDNSX = false
	config.Scan.DNSXWordlists = []string{uuid.NewString()}
	q.DB.Save(&config)
	c, e := q.Claim("worker")
	if e != nil || c != nil {
		t.Fatal(c, e)
	}
	var run models.ScanRun
	q.DB.First(&run, "profile_id=?", p.ID.String())
	if run.Status != "failed" {
		t.Fatal(run)
	}
	config.Scan.SkipDNSX = true
	q.DB.Save(&config)
	c, e = q.Claim("worker")
	if e != nil || c == nil || c.Job.ProfileID != next.ID.String() {
		t.Fatal("queue blocked", c, e)
	}
}
