package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/jobs"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/wordlists"
)

func TestWorkerEngineHelper(t *testing.T) {
	path := os.Getenv("ICEVIRTUE_ENGINE_HELPER")
	if path == "" {
		return
	}
	s, e := database.Open(path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var uploads *wordlists.Store
	if dir := os.Getenv("ICEVIRTUE_TEST_UPLOADS"); dir != "" {
		uploads, e = wordlists.OpenWorker(s.DB, dir)
		if e != nil {
			t.Fatal(e)
		}
		defer uploads.Close()
	}
	c := NewCoordinator(s.DB, uploads)
	c.SetTools(NewToolchain(os.Getenv("ICEVIRTUE_TEST_HOME"), os.Getenv("ICEVIRTUE_TEST_TOOLS"), ""))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	c.Start()
	<-ctx.Done()
	c.Stop()
}
func waitUntil(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}
func TestWorkerCrashLeaseLossAndShutdown(t *testing.T) {
	for _, mode := range []string{"crash", "lease-loss", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			s, e := database.Open(filepath.Join(dir, "shared.db"), true)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			config, _ := appconfig.Load(s.DB)
			config.Scan.SkipAmass = true
			config.Scan.SkipDNSX = true
			config.Scan.SkipWAF = true
			config.Scan.SkipSecrets = true
			config.Scan.SkipNuclei = true
			config.Scan.SkipDirectory = true
			s.DB.Save(&config)
			p := models.Profile{Domain: "example.test", Enabled: true}
			s.DB.Create(&p)
			q := &jobs.Queue{DB: s.DB}
			if e = q.Enqueue(p.ID.String(), "manual"); e != nil {
				t.Fatal(e)
			}
			subfinder := filepath.Join(dir, "subfinder")
			httpx := filepath.Join(dir, "httpx")
			marker := filepath.Join(dir, "process.pid")
			os.WriteFile(subfinder, []byte("#!/bin/sh\nprintf '%s\\n' '{\"host\":\"a.example.test\"}'\n"), 0700)
			os.WriteFile(httpx, []byte("#!/bin/sh\necho $$ > '"+marker+"'\n/bin/sleep 40\nprintf '%s\\n' '{\"url\":\"https://a.example.test\",\"status_code\":200}'\n"), 0700)
			cmd := exec.Command(os.Args[0], "-test.run=^TestWorkerEngineHelper$", "-test.timeout=50s")
			cmd.Env = append(os.Environ(), "ICEVIRTUE_ENGINE_HELPER="+filepath.Join(dir, "shared.db"), "ICEVIRTUE_TEST_HOME="+dir, "ICEVIRTUE_TEST_TOOLS=subfinder="+subfinder+",httpx="+httpx)
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			waitUntil(t, 5*time.Second, func() bool { _, e := os.Stat(marker); return e == nil })
			raw, _ := os.ReadFile(marker)
			pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
			defer syscall.Kill(-pid, syscall.SIGKILL)
			var job models.ScanJob
			s.DB.Where("profile_id=?", p.ID).First(&job)
			if job.RunID == "" {
				t.Fatal("run not created")
			}
			switch mode {
			case "crash":
				cmd.Process.Kill()
				cmd.Wait()
				s.DB.Model(&job).Update("lease_until", 0)
			case "lease-loss":
				s.DB.Model(&job).Update("token", "stolen-token")
				waitUntil(t, 14*time.Second, func() bool { return syscall.Kill(pid, 0) == syscall.ESRCH })
				s.DB.Model(&job).Update("lease_until", 0)
			case "shutdown":
				cmd.Process.Signal(syscall.SIGTERM)
				if e = cmd.Wait(); e != nil {
					t.Fatalf("shutdown %v: %s", e, output.String())
				}
				waitUntil(t, time.Second, func() bool { return syscall.Kill(pid, 0) == syscall.ESRCH })
			}
			if e = q.Reap(); e != nil {
				t.Fatal(e)
			}
			var count int64
			s.DB.Model(&models.Subdomain{}).Where("profile_id=?", p.ID).Count(&count)
			if count != 1 {
				t.Fatalf("partial findings lost: %d", count)
			}
			var run models.ScanRun
			s.DB.First(&run, "id=?", job.RunID)
			if run.Status != "interrupted" || run.NewFindings != 1 {
				t.Fatalf("run: %+v", run)
			}
			s.DB.Model(&models.ScanToolRun{}).Where("run_id=? AND status='running'", job.RunID).Count(&count)
			if count != 0 {
				t.Fatal("unfinished tool diagnostics")
			}
			if e = q.Finish(job, "completed", "completed"); !errors.Is(e, jobs.ErrLease) {
				t.Fatal("stale completion accepted", e)
			}
			if mode != "crash" && mode != "shutdown" {
				cmd.Process.Signal(syscall.SIGTERM)
				cmd.Wait()
			}
		})
	}
}
func TestPersistenceFailureRollsBackCountAndOutbox(t *testing.T) {
	p, _ := newPipelineEnv(t, "passive")
	r := testRunner()
	// A deterministic database failure after rows have been written rolls back the entire batch.
	if e := testDB.Exec("CREATE TRIGGER fail_outbox BEFORE INSERT ON outbox_events BEGIN SELECT RAISE(ABORT, 'injected write failure'); END").Error; e != nil {
		t.Fatal(e)
	}
	n, e := r.persistSubdomains(p, []string{"a.example.com"})
	if e == nil || n != 0 {
		t.Fatalf("count=%d error=%v", n, e)
	}
	var count int64
	testDB.Model(&models.Subdomain{}).Count(&count)
	if count != 0 {
		t.Fatal("finding escaped failed transaction")
	}
}
func TestFindingStoreRejectsReplacedToken(t *testing.T) {
	p, _ := newPipelineEnv(t, "passive")
	q := &jobs.Queue{DB: testDB}
	q.Enqueue(p.ID.String(), "manual")
	c, e := q.Claim("one")
	if e != nil {
		t.Fatal(e)
	}
	store := NewFindingStore(testDB, c.Job)
	testDB.Model(&models.ScanJob{}).Where("id=?", c.Job.ID).Update("token", "other")
	n, e := store.persistSubdomains(p, []string{"stale.example.com"})
	if !errors.Is(e, jobs.ErrLease) || n != 0 {
		t.Fatalf("count=%d error=%v", n, e)
	}
	var count int64
	testDB.Model(&models.Subdomain{}).Count(&count)
	if count != 0 {
		t.Fatal("stale worker wrote a finding")
	}
}
