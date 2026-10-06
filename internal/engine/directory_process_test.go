package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/jobs"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/wordlists"
	"gorm.io/gorm"
)

func TestDirectoryAcrossWorkerProcesses(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "shared.db")
	db, e := database.Open(dbPath, true)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	uploads, e := wordlists.New(db.DB, filepath.Join(dir, "uploads"), filepath.Join(dir, "web"))
	if e != nil {
		t.Fatal(e)
	}
	defer uploads.Close()
	var words strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&words, "path%d\n", i)
	}
	selected, e := uploads.Upload(context.Background(), "words.txt", "directory", "test", strings.NewReader(words.String()), func(*gorm.DB) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	var active, peak, controls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		defer active.Add(-1)
		time.Sleep(10 * time.Millisecond)
		if strings.Contains(r.URL.Path, "icevirtue-missing-") {
			controls.Add(1)
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "Confirmed application path "+r.URL.Path)
	}))
	defer server.Close()
	config, e := appconfig.Load(db.DB)
	if e != nil {
		t.Fatal(e)
	}
	config.Scan.SkipAmass = true
	config.Scan.SkipDNSX = true
	config.Scan.SkipWAF = true
	config.Scan.SkipSecrets = true
	config.Scan.SkipNuclei = true
	config.Scan.SkipDirectory = false
	config.Scan.DirectoryWordlists = []string{selected.ID}
	config.Tools.MaxConcurrentScans = 2
	if e = db.DB.Save(&config).Error; e != nil {
		t.Fatal(e)
	}
	subfinder, httpx := filepath.Join(dir, "subfinder"), filepath.Join(dir, "httpx")
	if e = os.WriteFile(subfinder, []byte("#!/bin/sh\nprintf '%s\\n' '{\"host\":\"127.0.0.1\"}'\n"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(httpx, []byte("#!/bin/sh\nprintf '%s\\n' '{\"url\":\""+server.URL+"\",\"status_code\":200}'\n"), 0700); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestWorkerEngineHelper$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "ICEVIRTUE_ENGINE_HELPER="+dbPath, "ICEVIRTUE_TEST_HOME="+dir, "ICEVIRTUE_TEST_TOOLS=subfinder="+subfinder+",httpx="+httpx, "ICEVIRTUE_TEST_UPLOADS="+uploads.Path)
		log, e := os.Create(filepath.Join(dir, fmt.Sprintf("worker%d.log", i)))
		if e != nil {
			t.Fatal(e)
		}
		cmd.Stdout = log
		cmd.Stderr = log
		if e = cmd.Start(); e != nil {
			log.Close()
			t.Fatal(e)
		}
		t.Cleanup(func() { cmd.Process.Signal(syscall.SIGTERM); cmd.Wait(); log.Close() })
	}
	waitUntil(t, 5*time.Second, func() bool { var n int64; db.DB.Model(&models.WorkerHeartbeat{}).Count(&n); return n == 2 })
	queue := &jobs.Queue{DB: db.DB}
	for i := 0; i < 4; i++ {
		p := models.Profile{Domain: fmt.Sprintf("profile%d.test", i), Enabled: true}
		if e = db.DB.Create(&p).Error; e != nil {
			t.Fatal(e)
		}
		if e = queue.Enqueue(p.ID.String(), "manual"); e != nil {
			t.Fatal(e)
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		var running, finished int64
		db.DB.Model(&models.ScanJob{}).Where("state='running'").Count(&running)
		if running > 2 {
			t.Fatal("global concurrency exceeded", running)
		}
		db.DB.Model(&models.ScanRun{}).Where("status='completed'").Count(&finished)
		if finished == 4 {
			break
		}
		if time.Now().After(deadline) {
			for i := 0; i < 2; i++ {
				raw, _ := os.ReadFile(filepath.Join(dir, fmt.Sprintf("worker%d.log", i)))
				t.Log(string(raw))
			}
			t.Fatal("scans did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if peak.Load() > 2*directoryWorkers {
		t.Fatal("combined request budget exceeded", peak.Load())
	}
	if controls.Load() != 12 {
		t.Fatal("baselines leaked between profile scans", controls.Load())
	}
	var n int64
	db.DB.Model(&models.DirectoryFinding{}).Where("assessment='confirmed'").Count(&n)
	if n != 400 {
		t.Fatal("missing or duplicate findings", n)
	}
	db.DB.Model(&models.WordlistPin{}).Count(&n)
	if n != 0 {
		t.Fatal("pins leaked", n)
	}
}
