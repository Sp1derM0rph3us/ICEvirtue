package engine

import (
	"context"
	"errors"
	"fmt"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/wordlists"
	"gorm.io/gorm"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCoordinatorAdmissionLimitsAndRecovery(t *testing.T) {
	p, _ := newPipelineEnv(t, "passive")
	c := NewCoordinator(database.DB, nil)
	defer c.cancel()
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- c.Enqueue(p.ID.String(), "manual") }()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for e := range results {
		if e == nil {
			accepted++
		} else if !errors.Is(e, ErrScanDuplicate) {
			t.Fatal(e)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d duplicate scans", accepted)
	}
	for i := 1; i < MaxQueuedScans; i++ {
		p := models.Profile{Domain: fmt.Sprintf("%d.example.test", i), Enabled: true}
		database.DB.Create(&p)
		if e := c.Enqueue(p.ID.String(), "manual"); e != nil {
			t.Fatal(e)
		}
	}
	extra := models.Profile{Domain: "extra.example.test", Enabled: true}
	database.DB.Create(&extra)
	if e := c.Enqueue(extra.ID.String(), "manual"); !errors.Is(e, ErrQueueFull) {
		t.Fatal(e)
	}
	database.DB.Model(&models.ScanJob{}).Where("profile_id = ?", p.ID).Update("state", "running")
	database.DB.Model(p).Update("is_scanning", true)
	if e := c.Recover(); e != nil {
		t.Fatal(e)
	}
	fresh := reloadProfile(t, p.ID)
	if fresh.IsScanning || !strings.Contains(fresh.LastScanStatus, "interrupted") {
		t.Fatalf("not recovered %+v", fresh)
	}
	var n int64
	database.DB.Model(&models.ScanJob{}).Count(&n)
	if n != 99 {
		t.Fatalf("queued jobs lost: %d", n)
	}
}
func TestCoordinatorSnapshotsSettingsAndPinsLists(t *testing.T) {
	p, _ := newPipelineEnv(t, "full")
	store, e := wordlists.New(database.DB, filepath.Join(t.TempDir(), "uploads"), filepath.Join(t.TempDir(), "web"))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	item, e := store.Upload(context.Background(), "list.txt", "directory", "test", strings.NewReader("admin\n"), func(*gorm.DB) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	configuration, _ := appconfig.Load(database.DB)
	configuration.Scan.SkipDirectory = false
	configuration.Scan.DirectoryWordlists = []string{item.ID}
	database.DB.Save(&configuration)
	c := NewCoordinator(database.DB, store)
	defer c.cancel()
	started := make(chan *runner, 4)
	release := make(chan struct{})
	c.execute = func(run *runner, p *models.Profile) {
		started <- run
		<-release
		database.DB.Model(p).Update("is_scanning", false)
	}
	defer func() { close(release); c.wg.Wait() }()
	for i := 0; i < 3; i++ {
		id := p.ID
		if i > 0 {
			other := models.Profile{Domain: fmt.Sprintf("queued%d.test", i), Enabled: true}
			database.DB.Create(&other)
			id = other.ID
		}
		if e = c.Enqueue(id.String(), "manual"); e != nil {
			t.Fatal(e)
		}
	}
	configuration.Tools.WAFTimeoutSeconds = 44
	configuration.Revision = 2
	database.DB.Save(&configuration)
	for i := 0; i < 3; i++ {
		if e = c.dispatch(); e != nil {
			t.Fatal(e)
		}
	}
	var first *runner
	for i := 0; i < 2; i++ {
		select {
		case r := <-started:
			first = r
		case <-time.After(time.Second):
			t.Fatal("worker not dispatched")
		}
	}
	select {
	case <-started:
		t.Fatal("concurrency limit exceeded")
	default:
	}
	configuration.Tools.WAFTimeoutSeconds = 99
	configuration.Scan.DirectoryWordlists = []string{}
	configuration.Scan.SkipDirectory = true
	database.DB.Save(&configuration)
	if first.wafTimeout != 44*time.Second || first.config.Revision != 2 || len(first.directoryPaths) != 1 {
		t.Fatal("scan did not retain start snapshot")
	}
	if e = store.Delete(item.ID, func(*gorm.DB) error { return nil }); !errors.Is(e, wordlists.ErrInUse) {
		t.Fatalf("running list deletion allowed: %v", e)
	}
}
func TestDisabledLeafStagesDoNotExecuteTools(t *testing.T) {
	p, _ := newPipelineEnv(t, "full")
	run := testRunner()
	run.config.Scan.SkipNuclei = true
	run.config.Scan.SkipSecrets = true
	run.config.Scan.SkipDirectory = true
	_, n := run.stageVulns(p, nil)
	_, s := run.stageSecrets(p, nil)
	_, d := run.stageFuzzing(p, nil)
	if n.attempted() != 0 || s.attempted() != 0 || d.attempted() != 0 {
		t.Fatal("disabled stage attempted tools")
	}
}
