package api

import (
	"encoding/json"
	"fmt"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDirectoryAssessmentFiltersCountsAndRootStatus(t *testing.T) {
	p := newAPIEnv(t)
	testDB.Create(&models.Subdomain{ProfileID: p.ID, Domain: "x.example.com"})
	testDB.Create(&models.AliveHost{ProfileID: p.ID, URL: "https://x.example.com", StatusCode: 302})
	for i, a := range []string{"confirmed", "unknown", "unknown", "legacy"} {
		if e := testDB.Create(&models.DirectoryFinding{ProfileID: p.ID, SubdomainURL: "https://x.example.com", DirURL: fmt.Sprintf("https://x.example.com/d%d", i), StatusCode: 302, Assessment: a}).Error; e != nil {
			t.Fatal(e)
		}
	}
	for _, tc := range []struct {
		assessment string
		count      int64
	}{{"all", 4}, {"confirmed", 1}, {"unknown", 2}, {"invalid", 4}} {
		rec := doGet(t, fmt.Sprintf("/api/profiles/%s/directories?host=x.example.com&assessment=%s&size=1&page=99", p.ID, tc.assessment), testAPI().getProfileDirectories)
		page := decodePage[models.DirectoryFinding](t, rec, "directory assessment")
		if page.Page.TotalRows != tc.count || page.Page.Page != int(tc.count) || len(page.Data) != 1 {
			t.Fatal(tc, page)
		}
		if tc.assessment == "invalid" && page.Page.Assessment != "all" {
			t.Fatal("invalid assessment not normalized")
		}
	}
	page := getSubdomainPage(t, p.ID, "?filter=unknown-directories")
	if page.Page.TotalRows != 1 {
		t.Fatal(page)
	}
	row := page.Data[0]
	if row.StatusCode == nil || *row.StatusCode != 302 || row.ConfirmedDirCount != 1 || row.UnknownDirCount != 2 || row.LegacyDirCount != 1 {
		t.Fatal(row)
	}
	page = getSubdomainPage(t, p.ID, "?filter=status-2xx-3xx")
	if page.Page.TotalRows != 1 {
		t.Fatal("root status filter changed")
	}
}
func TestRedirectListsAreScopedAndPaginated(t *testing.T) {
	p := newAPIEnv(t)
	for i := 0; i < 7; i++ {
		r := models.RedirectObservation{ProfileID: p.ID, Host: "x.example.com", SourceURL: fmt.Sprintf("https://x.example.com/d%d", i), DestinationHost: fmt.Sprintf("y%d.example.com", i), DestinationURL: "https://y.example.com", Kind: "cross_host", PreviouslyEnumerated: i%2 == 0}
		if e := testDB.Create(&r).Error; e != nil {
			t.Fatal(e)
		}
	}
	testDB.Create(&models.RedirectObservation{ProfileID: p.ID, Host: "other.example.com", SourceURL: "https://other.example.com", DestinationHost: "external.com", Kind: "cross_scope"})
	rec := doGet(t, fmt.Sprintf("/api/profiles/%s/redirects?host=x.example.com&size=2&page=2", p.ID), testAPI().getProfileRedirects)
	page := decodePage[models.RedirectObservation](t, rec, "redirects")
	if len(page.Data) != 2 || page.Page.TotalRows != 7 || page.Page.Page != 2 {
		t.Fatal(page)
	}
	rec = doGet(t, fmt.Sprintf("/api/profiles/%s/redirects/summary?host=x.example.com", p.ID), testAPI().getRedirectSummary)
	var summary []redirectSummary
	if e := json.Unmarshal(rec.Body.Bytes(), &summary); e != nil {
		t.Fatal(e)
	}
	if len(summary) != 6 {
		t.Fatal(summary)
	}
	rec = doGet(t, fmt.Sprintf("/api/profiles/%s/redirects", p.ID), testAPI().getProfileRedirects)
	page = decodePage[models.RedirectObservation](t, rec, "missing host")
	if page.Page.TotalRows != 0 {
		t.Fatal("unscoped redirects exposed")
	}
	other := models.Profile{Domain: "other.test"}
	testDB.Create(&other)
	rec = doGet(t, fmt.Sprintf("/api/profiles/%s/redirects?host=x.example.com", other.ID), testAPI().getProfileRedirects)
	page = decodePage[models.RedirectObservation](t, rec, "other profile")
	if page.Page.TotalRows != 0 {
		t.Fatal("other profile leaked")
	}
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
}

func doGet(t *testing.T, target string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	segments := strings.Split(strings.SplitN(target, "?", 2)[0], "/")
	segments[3] = "{id}"
	return route(t, http.MethodGet, strings.Join(segments, "/"), target, handler)
}
