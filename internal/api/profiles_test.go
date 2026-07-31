package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// TestConcurrentCreateYieldsOneCreatedAndTheRest409 is the regression test for the
// duplicate-domain TOCTOU. The pre-check let two requests both find nothing and both
// insert; the loser surfaced the raw driver error as a 500, telling the client the server
// had broken when its request had simply lost a race.
func TestConcurrentCreateYieldsOneCreatedAndTheRest409(t *testing.T) {
	newAPIEnv(t)
	initAuth(t)
	h := newServerWithUsers(t)
	cookie := sessionCookie(t, time.Hour)

	const callers = 25
	codes := make([]int, callers)

	var release sync.WaitGroup
	var done sync.WaitGroup
	release.Add(1)

	for i := range callers {
		done.Add(1)
		go func(slot int) {
			defer done.Done()
			release.Wait()
			rec := postJSON(t, h, "/api/profiles",
				`{"domain":"race.example.com","schedule":"every day at 03:00"}`, cookie)
			codes[slot] = rec.Code
		}(i)
	}

	release.Done()
	done.Wait()

	created, conflict, other := 0, 0, 0
	for _, code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflict++
		default:
			other++
			t.Logf("unexpected status %d", code)
		}
	}

	if created != 1 || conflict != callers-1 || other != 0 {
		t.Errorf("%d concurrent creates produced %d created, %d conflict, %d other; want 1, %d, 0",
			callers, created, conflict, other, callers-1)
	}

	var rows int64
	database.DB.Model(&models.Profile{}).Where("domain = ?", "race.example.com").Count(&rows)
	if rows != 1 {
		t.Errorf("the database holds %d rows for the domain, want 1", rows)
	}
}

func TestCreateProfileRejectsAnInvalidSchedule(t *testing.T) {
	newAPIEnv(t)
	initAuth(t)
	h := newServerWithUsers(t)

	rec := postJSON(t, h, "/api/profiles",
		`{"domain":"bad-schedule.example.com","schedule":"whenever I feel like it"}`,
		sessionCookie(t, time.Hour))

	// ParseSchedule was only ever called at Sync time, where a failure is logged and
	// skipped, so this used to be stored and answered 200 — a profile that never fires.
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unparseable schedule = %d, want 400", rec.Code)
	}

	var rows int64
	database.DB.Model(&models.Profile{}).Where("domain = ?", "bad-schedule.example.com").Count(&rows)
	if rows != 0 {
		t.Error("the profile was stored despite the invalid schedule")
	}
}

// TestDeleteHardDeletesChildren is the strengthened version of the old test.
//
// Every child model carries gorm.DeletedAt and the handler used a plain Delete, so the
// rows were only soft-deleted: invisible to the dashboard's scoped queries but still in
// the file, owned by a profile that no longer existed. The previous test counted without
// Unscoped(), so it passed over exactly that bug.
func TestDeleteHardDeletesChildren(t *testing.T) {
	profile := newAPIEnv(t)
	initAuth(t)
	h := newServerWithUsers(t)
	id := profile.ID

	seed := []interface{}{
		&models.Subdomain{ProfileID: id, Domain: "a.example.com"},
		&models.AliveHost{ProfileID: id, URL: "https://a.example.com"},
		&models.Vulnerability{ProfileID: id, TemplateID: "t", URL: "https://a.example.com", Severity: "info"},
		&models.SecretFinding{ProfileID: id, SourceURL: "https://a.example.com/x.js", SecretType: "aws", SecretValue: "AKIA"},
		&models.DirectoryFinding{ProfileID: id, SubdomainURL: "https://a.example.com", DirURL: "https://a.example.com/admin"},
	}
	for _, row := range seed {
		if err := database.DB.Create(row).Error; err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/profiles/"+id.String(), nil)
	req.AddCookie(sessionCookie(t, time.Hour))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204: %s", rec.Code, rec.Body.String())
	}

	for _, table := range []string{"subdomains", "alive_hosts", "vulnerabilities", "secret_findings", "directory_findings"} {
		var n int64
		// Raw SQL, so no soft-delete scope can hide a surviving row.
		if err := database.DB.Raw("SELECT COUNT(*) FROM "+table+" WHERE profile_id = ?", id).Scan(&n).Error; err != nil {
			t.Fatalf("counting %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s still holds %d row(s) for the deleted profile", table, n)
		}
	}
}

// TestDeleteIsRefusedWhileScanning covers the interaction with the scan lock. Deleting a
// profile mid-scan let the running pipeline write findings for a profile that no longer
// existed, recreating the orphans the handler exists to prevent.
func TestDeleteIsRefusedWhileScanning(t *testing.T) {
	profile := newAPIEnv(t)
	initAuth(t)
	h := newServerWithUsers(t)
	id := profile.ID

	if err := database.DB.Create(&models.Subdomain{ProfileID: id, Domain: "a.example.com"}).Error; err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if err := database.DB.Model(&models.Profile{}).Where("id = ?", id).
		Update("is_scanning", true).Error; err != nil {
		t.Fatalf("seeding the scan lock: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/profiles/"+id.String(), nil)
	req.AddCookie(sessionCookie(t, time.Hour))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("deleting a scanning profile = %d, want 409", rec.Code)
	}

	var children int64
	database.DB.Raw("SELECT COUNT(*) FROM subdomains WHERE profile_id = ?", id).Scan(&children)
	if children != 1 {
		t.Errorf("the refused delete removed %d child row(s); it must remove none", 1-children)
	}

	// And the lock it did not take must still be held by the run that owns it.
	var scanning bool
	database.DB.Raw("SELECT is_scanning FROM profiles WHERE id = ?", id).Scan(&scanning)
	if !scanning {
		t.Error("the refused delete released a scan lock it never held")
	}
}

func TestDeleteReleasesTheLockOnFailure(t *testing.T) {
	profile := newAPIEnv(t)
	initAuth(t)
	h := newServerWithUsers(t)

	// A profile that exists and is not scanning: the delete succeeds, and afterwards there
	// is no row left to hold a lock. The point of this test is the inverse case — that a
	// successful delete does not leave is_scanning set on a row it removed — which is
	// covered by the row being gone.
	req := httptest.NewRequest(http.MethodDelete, "/api/profiles/"+profile.ID.String(), nil)
	req.AddCookie(sessionCookie(t, time.Hour))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", rec.Code)
	}

	var rows int64
	database.DB.Raw("SELECT COUNT(*) FROM profiles WHERE id = ?", profile.ID).Scan(&rows)
	if rows != 0 {
		t.Error("the profile row survived a successful delete")
	}
}

func TestDeleteOfAnUnknownProfileIs404(t *testing.T) {
	newAPIEnv(t)
	initAuth(t)
	h := newServerWithUsers(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/profiles/"+uuid.NewString(), nil)
	req.AddCookie(sessionCookie(t, time.Hour))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("deleting an unknown profile = %d, want 404", rec.Code)
	}
}

// TestEditScheduleReturnsTheValueItWrote is the regression test for the stale read. The
// handler loaded the profile, updated the column, and then returned the Schedule from the
// struct it had loaded before the update.
func TestEditScheduleReturnsTheValueItWrote(t *testing.T) {
	profile := newAPIEnv(t)
	initAuth(t)
	h := newServerWithUsers(t)

	const want = "every week at 04:15"
	req := httptest.NewRequest(http.MethodPut, "/api/profiles/"+profile.ID.String()+"/schedule",
		strings.NewReader(fmt.Sprintf(`{"schedule":%q}`, want)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie(t, time.Hour))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), want) {
		t.Errorf("the response echoed %s, want the new value %q", rec.Body.String(), want)
	}

	var stored string
	database.DB.Raw("SELECT schedule FROM profiles WHERE id = ?", profile.ID).Scan(&stored)
	if stored != want {
		t.Errorf("the stored schedule is %q, want %q", stored, want)
	}
}

func TestEditScheduleRejectsAnUnparseableValue(t *testing.T) {
	profile := newAPIEnv(t)
	initAuth(t)
	h := newServerWithUsers(t)

	var before string
	database.DB.Raw("SELECT schedule FROM profiles WHERE id = ?", profile.ID).Scan(&before)

	req := httptest.NewRequest(http.MethodPut, "/api/profiles/"+profile.ID.String()+"/schedule",
		strings.NewReader(`{"schedule":"whenever"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie(t, time.Hour))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unparseable schedule = %d, want 400", rec.Code)
	}

	var after string
	database.DB.Raw("SELECT schedule FROM profiles WHERE id = ?", profile.ID).Scan(&after)
	if after != before {
		t.Errorf("the stored schedule changed from %q to %q despite the 400", before, after)
	}
}

func TestEditScheduleOnAnUnknownProfileIs404(t *testing.T) {
	newAPIEnv(t)
	initAuth(t)
	h := newServerWithUsers(t)

	req := httptest.NewRequest(http.MethodPut, "/api/profiles/"+uuid.NewString()+"/schedule",
		strings.NewReader(`{"schedule":"every day at 05:00"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie(t, time.Hour))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("rescheduling an unknown profile = %d, want 404", rec.Code)
	}
}
