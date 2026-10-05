package app

import (
	"bytes"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestWorkerApplicationHelper(t *testing.T) {
	path := os.Getenv("ICEVIRTUE_APP_HELPER")
	if path == "" {
		return
	}
	dir := filepath.Dir(path)
	if e := RunWorker([]string{"--db-path", path, "--upload-dir", filepath.Join(dir, "uploads"), "--tool-home", dir, "--tool-paths", "subfinder=/bin/false,httpx=/bin/false,amass=/bin/false,dnsx=/bin/false,nuclei=/bin/false,wafw00f=/bin/false,waymore=/bin/false,katana=/bin/false,subjs=/bin/false,mantra=/bin/false,secrethound=/bin/false"}); e != nil {
		t.Fatal(e)
	}
}
func TestWorkerSchedulesAndScansWithoutWebServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.db")
	os.Mkdir(filepath.Join(dir, "uploads"), 0700)
	store, e := database.Open(path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	c, _ := appconfig.Load(store.DB)
	c.Scan.SkipAmass = true
	c.Scan.SkipDNSX = true
	c.Scan.SkipDirectory = true
	c.Scan.SkipWAF = true
	c.Scan.SkipSecrets = true
	c.Scan.SkipNuclei = true
	store.DB.Save(&c)
	p := models.Profile{Domain: "offline.test", Mode: "passive", Enabled: true, Schedule: "@every 1s"}
	store.DB.Create(&p)
	cmd := exec.Command(os.Args[0], "-test.run=^TestWorkerApplicationHelper$", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), "ICEVIRTUE_APP_HELPER="+path)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	complete := false
	for until := time.Now().Add(8 * time.Second); time.Now().Before(until); {
		var n int64
		store.DB.Model(&models.ScanRun{}).Where("source='scheduled' AND status='halted'").Count(&n)
		if n > 0 {
			complete = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	if e = cmd.Wait(); e != nil {
		t.Fatalf("worker exit: %v %s", e, logs.String())
	}
	if !complete {
		t.Fatalf("worker failed to schedule while HTTP was absent: %s", logs.String())
	}
}
