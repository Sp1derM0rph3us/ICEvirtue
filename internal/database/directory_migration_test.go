package database

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"path/filepath"
	"testing"
)

func TestDirectoryMigrationPreservesLegacyAndWorkerOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	store, e := Open(path, true)
	if e != nil {
		t.Fatal(e)
	}
	p := models.Profile{Domain: "example.com", Enabled: true}
	store.DB.Create(&p)
	store.DB.Create(&models.ScanJob{ProfileID: p.ID.String(), State: "running", Token: "preserved", Owner: "worker"})
	store.DB.Create(&models.WordlistPin{JobID: 1, WordlistID: "pin"})
	store.DB.Create(&models.DirectoryFinding{ProfileID: p.ID, SubdomainURL: "https://x.example.com", DirURL: "https://x.example.com/admin", StatusCode: 301})
	store.DB.Exec("DROP INDEX idx_dir_assessment")
	store.DB.Exec("ALTER TABLE directory_findings DROP COLUMN assessment")
	store.DB.Exec("ALTER TABLE directory_findings DROP COLUMN assessment_reason")
	store.DB.Where("version=?", models.ModularitySchema).Delete(&models.SchemaMigration{})
	store.Close()
	if s, e := Open(path, false); e == nil {
		s.Close()
		t.Fatal("worker accepted old directory schema")
	}
	store, e = Open(path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	var row models.DirectoryFinding
	store.DB.First(&row)
	if row.Assessment != "legacy" || row.StatusCode != 301 {
		t.Fatal(row)
	}
	var job models.ScanJob
	store.DB.First(&job)
	if job.Token != "preserved" || job.Owner != "worker" {
		t.Fatal("upgrade reset worker ownership", job)
	}
	var pins int64
	store.DB.Model(&models.WordlistPin{}).Count(&pins)
	if pins != 1 {
		t.Fatal("pins lost", pins)
	}
	if !store.DB.Migrator().HasTable(&models.RedirectObservation{}) {
		t.Fatal("redirect schema absent")
	}
	worker, e := Open(path, false)
	if e != nil {
		t.Fatal(e)
	}
	worker.Close()
}
