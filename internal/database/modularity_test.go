package database

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"path/filepath"
	"testing"
)

func TestWorkerRequiresSchemaAndMigrationPreservesQueue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	if s, e := Open(path, false); e == nil {
		s.Close()
		t.Fatal("worker created absent schema")
	}
	s, e := Open(path, true)
	if e != nil {
		t.Fatal(e)
	}
	p := models.Profile{Domain: "queued.test", Enabled: true}
	r := models.Profile{Domain: "running.test", Enabled: true}
	s.DB.Create(&p)
	s.DB.Create(&r)
	s.DB.Create(&models.ScanJob{ProfileID: p.ID.String(), State: "queued"})
	s.DB.Create(&models.ScanJob{ProfileID: r.ID.String(), State: "running"})
	s.DB.Exec("ALTER TABLE profiles ADD COLUMN is_scanning numeric")
	s.DB.Exec("ALTER TABLE profiles ADD COLUMN is_queued numeric")
	s.DB.Where("version=?", models.ModularitySchema).Delete(&models.SchemaMigration{})
	s.DB.Where("id=1").Delete(&models.SchedulerLease{})
	s.Close()
	if worker, e := Open(path, false); e == nil {
		worker.Close()
		t.Fatal("worker accepted old schema")
	}
	s, e = Open(path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for _, name := range []string{"is_scanning", "is_queued"} {
		if s.DB.Migrator().HasColumn("profiles", name) {
			t.Fatalf("legacy %s retained", name)
		}
	}
	var queued models.Profile
	if e = s.DB.First(&queued, "id=?", p.ID).Error; e != nil {
		t.Fatal(e)
	}
	if !queued.IsQueued || queued.IsScanning {
		t.Fatal("queue-derived state lost", queued)
	}
	var running models.Profile
	s.DB.First(&running, "id=?", r.ID)
	if running.IsScanning || running.LastScanStatus != "interrupted: upgrade" {
		t.Fatal(running)
	}
	worker, e := Open(path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer worker.Close()
	var jobs int64
	worker.DB.Model(&models.ScanJob{}).Count(&jobs)
	if jobs != 1 {
		t.Fatal("queue lost")
	}
}
