package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/jobs"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func TestDirectoryAssessmentCountsAndFences(t *testing.T) {
	p, _ := newPipelineEnv(t, "passive")
	q := &jobs.Queue{DB: testDB}
	if e := q.Enqueue(p.ID.String(), "manual"); e != nil {
		t.Fatal(e)
	}
	claim, e := q.Claim("worker")
	if e != nil || claim == nil {
		t.Fatal(e)
	}
	store := NewFindingStore(testDB, claim.Job)
	row := models.DirectoryFinding{SubdomainURL: "https://x.example.com", DirURL: "https://x.example.com/admin", StatusCode: 302, Assessment: "unknown", AssessmentReason: "matches_missing_paths"}
	redirect := models.RedirectObservation{Host: "x.example.com", SourceURL: row.DirURL, DestinationHost: "y.example.com", DestinationURL: "https://y.example.com/login", Kind: "cross_host"}
	n, e := store.storeDirectoryObservations(p.ID, []models.DirectoryFinding{row}, []models.RedirectObservation{redirect})
	if e != nil || n != 0 {
		t.Fatal(n, e)
	}
	var outbox models.OutboxEvent
	testDB.Order("id DESC").First(&outbox)
	var counts map[string]int
	json.Unmarshal([]byte(outbox.Data), &counts)
	if counts["directories"] != 0 || counts["unknown_directories"] != 1 {
		t.Fatal(counts)
	}
	row.Assessment = "confirmed"
	row.AssessmentReason = "distinct_from_missing_paths"
	row.StatusCode = 200
	n, e = store.storeDirectoryObservations(p.ID, []models.DirectoryFinding{row}, nil)
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	n, e = store.storeDirectoryObservations(p.ID, []models.DirectoryFinding{row}, []models.RedirectObservation{redirect})
	if e != nil || n != 0 {
		t.Fatal(n, e)
	}
	var run models.ScanRun
	testDB.First(&run, "id=?", claim.Job.RunID)
	if run.NewFindings != 1 {
		t.Fatal(run.NewFindings)
	}
	var duplicates int64
	testDB.Model(&models.RedirectObservation{}).Count(&duplicates)
	if duplicates != 1 {
		t.Fatal(duplicates)
	}
	testDB.Model(&models.ScanJob{}).Where("id=?", claim.Job.ID).Update("token", "replacement")
	row.DirURL += "-stale"
	redirect.SourceURL = row.DirURL
	n, e = store.storeDirectoryObservations(p.ID, []models.DirectoryFinding{row}, []models.RedirectObservation{redirect})
	if n != 0 || !errors.Is(e, jobs.ErrLease) {
		t.Fatal(n, e)
	}
	testDB.Model(&models.DirectoryFinding{}).Count(&duplicates)
	if duplicates != 1 {
		t.Fatal("stale directory write", duplicates)
	}
	testDB.Model(&models.RedirectObservation{}).Count(&duplicates)
	if duplicates != 1 {
		t.Fatal("stale redirect write", duplicates)
	}
}
func TestDirectoryWriteRollback(t *testing.T) {
	p, _ := newPipelineEnv(t, "passive")
	run := testRunner()
	testDB.Exec("CREATE TRIGGER fail_directory_outbox BEFORE INSERT ON outbox_events BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
	row := models.DirectoryFinding{SubdomainURL: "https://x.example.com", DirURL: "https://x.example.com/admin", StatusCode: 200, Assessment: "confirmed"}
	redirect := models.RedirectObservation{Host: "x.example.com", SourceURL: row.DirURL, DestinationURL: "https://other.com", DestinationHost: "other.com", Kind: "cross_scope"}
	n, e := run.storeDirectoryObservations(p, []models.DirectoryFinding{row}, []models.RedirectObservation{redirect})
	if n != 0 || e == nil {
		t.Fatal(n, e)
	}
	for _, m := range []any{&models.DirectoryFinding{}, &models.RedirectObservation{}} {
		var count int64
		testDB.Model(m).Count(&count)
		if count != 0 {
			t.Fatal("finding escaped rollback", count)
		}
	}
}
func TestRootRedirectPreservesRootStatusWithDirectoriesDisabled(t *testing.T) {
	p, _ := newPipelineEnv(t, "passive")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://y.example.com/login")
		w.WriteHeader(301)
		fmt.Fprint(w, "Redirect")
	}))
	defer server.Close()
	host := models.AliveHost{ProfileID: p.ID, URL: server.URL, StatusCode: 301}
	if e := testDB.Create(&host).Error; e != nil {
		t.Fatal(e)
	}
	run := testRunner()
	run.config.Scan.SkipDirectory = true
	run.knownHosts = map[string]bool{"y.example.com": true}
	n, e := run.inspectRootRedirects(p, []models.AliveHost{host})
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	var stored models.AliveHost
	testDB.First(&stored, host.ID)
	if stored.StatusCode != 301 {
		t.Fatal("root status changed", stored.StatusCode)
	}
	var redirect models.RedirectObservation
	testDB.First(&redirect)
	if redirect.Kind != "cross_host" || !redirect.PreviouslyEnumerated || redirect.SourceURL != server.URL {
		t.Fatal(redirect)
	}
}
func TestDirectoryPartialFindingsSurviveCancellation(t *testing.T) {
	p, _ := newPipelineEnv(t, "passive")
	run := testRunner()
	row := models.DirectoryFinding{SubdomainURL: "https://x.example.com", DirURL: "https://x.example.com/admin", StatusCode: 302, Assessment: "unknown"}
	if _, e := run.storeDirectoryBatch(p, []models.DirectoryFinding{row}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(run.ctx)
	cancel()
	run.ctx = ctx
	if _, e := run.RunDirectoryFuzzing(p, nil, nil); e == nil {
		t.Fatal("canceled scan continued")
	}
	var count int64
	testDB.Model(&models.DirectoryFinding{}).Count(&count)
	if count != 1 {
		t.Fatal("committed Unknown lost", count)
	}
}
