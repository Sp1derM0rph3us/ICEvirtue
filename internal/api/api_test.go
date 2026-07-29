package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// newAPIEnv gives the test an isolated SQLite database and one profile, following
// the same pattern the engine tests use: swap the package-level handle and put
// the previous one back on cleanup, so tests cannot see each other's rows.
func newAPIEnv(t *testing.T) *models.Profile {
	t.Helper()

	prevDB := database.DB
	t.Cleanup(func() { database.DB = prevDB })

	if err := database.InitDatabase(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDatabase: %v", err)
	}

	profile := &models.Profile{Domain: "example.com", Mode: "full", Schedule: "@every 24h", Enabled: true}
	if err := database.DB.Create(profile).Error; err != nil {
		t.Fatalf("creating profile: %v", err)
	}
	return profile
}

// route serves one request through a chi router carrying the given pattern, so
// the handler's chi.URLParam lookups resolve exactly as they do in production.
func route(t *testing.T, method, pattern, target string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()

	r := chi.NewRouter()
	r.Method(method, pattern, handler)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestParsePaginationClampsAnOversizedLimit(t *testing.T) {
	// The dashboard asks for more than one page on purpose. Rejecting the value
	// silently fell back to the default, so the caller received 250 rows while
	// believing it had asked for and received everything.
	cases := []struct {
		query string
		limit int
		offet int
	}{
		{"", defaultPageSize, 0},
		{"?limit=5000", maxPageSize, 0},
		{"?limit=1001", maxPageSize, 0},
		{"?limit=1000", maxPageSize, 0},
		{"?limit=500", 500, 0},
		{"?limit=0", defaultPageSize, 0},
		{"?limit=-7", defaultPageSize, 0},
		{"?limit=abc", defaultPageSize, 0},
		{"?offset=250", defaultPageSize, 250},
		{"?offset=-1", defaultPageSize, 0},
		{"?limit=5000&offset=2000", maxPageSize, 2000},
	}

	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/api/profiles/x/subdomains"+c.query, nil)
		limit, offset := parsePagination(req)

		if limit != c.limit || offset != c.offet {
			t.Errorf("parsePagination(%q) = (%d, %d), want (%d, %d)", c.query, limit, offset, c.limit, c.offet)
		}
	}
}

// TestFindingEndpointPagesToTheEnd is the end-to-end guard for the truncation
// bug: a profile with more findings than one page must be reachable in full by
// paging, and the first page must be a clamped maxPageSize rather than the
// default.
func TestFindingEndpointPagesToTheEnd(t *testing.T) {
	profile := newAPIEnv(t)

	const total = maxPageSize + 200
	for i := range total {
		sub := models.Subdomain{ProfileID: profile.ID, Domain: fmt.Sprintf("host-%04d.example.com", i)}
		if err := database.DB.Create(&sub).Error; err != nil {
			t.Fatalf("seeding subdomain %d: %v", i, err)
		}
	}

	page := func(query string) []models.Subdomain {
		t.Helper()

		rec := route(t, http.MethodGet, "/api/profiles/{id}/subdomains",
			"/api/profiles/"+profile.ID.String()+"/subdomains"+query, getProfileSubdomains)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", query, rec.Code)
		}

		var got []models.Subdomain
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decoding %s: %v", query, err)
		}
		return got
	}

	first := page("?limit=5000")
	if len(first) != maxPageSize {
		t.Fatalf("first page returned %d rows, want the clamped %d", len(first), maxPageSize)
	}

	second := page(fmt.Sprintf("?limit=5000&offset=%d", maxPageSize))
	if len(second) != total-maxPageSize {
		t.Fatalf("second page returned %d rows, want %d", len(second), total-maxPageSize)
	}

	// A short page is how the client knows it has reached the end, so the two
	// pages together must account for every row exactly once.
	seen := make(map[string]bool, total)
	for _, s := range append(first, second...) {
		if seen[s.Domain] {
			t.Fatalf("%s was returned by more than one page", s.Domain)
		}
		seen[s.Domain] = true
	}
	if len(seen) != total {
		t.Fatalf("paging covered %d distinct rows, want %d", len(seen), total)
	}
}

// TestDeleteProfileRemovesEveryChildTable guards the orphan bug. Every finding
// table a stage can write to has to be cleaned up; directory findings used to be
// left behind because they were simply missing from the handler.
func TestDeleteProfileRemovesEveryChildTable(t *testing.T) {
	profile := newAPIEnv(t)
	id := profile.ID

	seed := []struct {
		name string
		row  interface{}
	}{
		{"subdomain", &models.Subdomain{ProfileID: id, Domain: "a.example.com"}},
		{"alive host", &models.AliveHost{ProfileID: id, URL: "https://a.example.com"}},
		{"vulnerability", &models.Vulnerability{ProfileID: id, TemplateID: "t", URL: "https://a.example.com", Severity: "info"}},
		{"secret", &models.SecretFinding{ProfileID: id, SourceURL: "https://a.example.com/x.js", SecretType: "aws", SecretValue: "AKIA"}},
		{"directory", &models.DirectoryFinding{ProfileID: id, SubdomainURL: "https://a.example.com", DirURL: "https://a.example.com/admin", StatusCode: 200}},
	}
	for _, s := range seed {
		if err := database.DB.Create(s.row).Error; err != nil {
			t.Fatalf("seeding %s: %v", s.name, err)
		}
	}

	rec := route(t, http.MethodDelete, "/api/profiles/{id}", "/api/profiles/"+id.String(), deleteProfile)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE returned %d, want 204: %s", rec.Code, rec.Body.String())
	}

	tables := []struct {
		name  string
		model interface{}
	}{
		{"subdomains", &models.Subdomain{}},
		{"alive_hosts", &models.AliveHost{}},
		{"vulnerabilities", &models.Vulnerability{}},
		{"secret_findings", &models.SecretFinding{}},
		{"directory_findings", &models.DirectoryFinding{}},
	}
	for _, tbl := range tables {
		var n int64
		if err := database.DB.Model(tbl.model).Where("profile_id = ?", id).Count(&n).Error; err != nil {
			t.Fatalf("counting %s: %v", tbl.name, err)
		}
		if n != 0 {
			t.Errorf("%s still holds %d row(s) for the deleted profile", tbl.name, n)
		}
	}

	var profiles int64
	if err := database.DB.Unscoped().Model(&models.Profile{}).Where("id = ?", id).Count(&profiles).Error; err != nil {
		t.Fatalf("counting profiles: %v", err)
	}
	if profiles != 0 {
		t.Errorf("the profile row survived the delete")
	}
}

func TestDeleteProfileRejectsABadID(t *testing.T) {
	newAPIEnv(t)

	rec := route(t, http.MethodDelete, "/api/profiles/{id}", "/api/profiles/not-a-uuid", deleteProfile)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("DELETE with a malformed id returned %d, want 400", rec.Code)
	}

	rec = route(t, http.MethodDelete, "/api/profiles/{id}", "/api/profiles/"+uuid.NewString(), deleteProfile)
	if rec.Code != http.StatusNotFound {
		t.Errorf("DELETE of an unknown profile returned %d, want 404", rec.Code)
	}
}
