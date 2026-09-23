package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func TestProfileOverviewCountsAndPriority(t *testing.T) {
	profile := newAPIEnv(t)
	other := &models.Profile{Domain: "other.example.com"}
	if err := database.DB.Create(other).Error; err != nil {
		t.Fatal(err)
	}

	scan := time.Date(2026, 9, 22, 15, 30, 0, 0, time.UTC)
	if err := database.DB.Model(profile).Updates(map[string]interface{}{
		"last_scan": scan, "last_scan_status": "completed",
	}).Error; err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.example.com", "b.example.com", "localhost"} {
		if err := database.DB.Create(&models.Subdomain{ProfileID: profile.ID, Domain: name}).Error; err != nil {
			t.Fatal(err)
		}
	}
	changed := scan.Add(-time.Hour)
	if err := database.DB.Model(&models.Subdomain{}).Where("profile_id = ?", profile.ID).
		UpdateColumn("last_changed", scan.Add(-2*time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Model(&models.Subdomain{}).
		Where("profile_id = ? AND domain = ?", profile.ID, "a.example.com").
		UpdateColumn("last_changed", changed).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Create(&models.AliveHost{ProfileID: profile.ID, URL: "http://a.example.com", StatusCode: 301}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Create(&models.AliveHost{ProfileID: profile.ID, URL: "https://a.example.com", StatusCode: 200}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Create(&models.AliveHost{ProfileID: profile.ID, URL: "https://unlisted.example.com", StatusCode: 200}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Create(&models.AliveHost{ProfileID: other.ID, URL: "https://b.example.com", StatusCode: 200}).Error; err != nil {
		t.Fatal(err)
	}

	addFinding := func(severity, name, url string, n int) {
		t.Helper()
		finding := &models.Vulnerability{
			ProfileID: profile.ID, TemplateID: fmt.Sprintf("tpl-%d", n),
			URL: url, Severity: severity, Name: name,
		}
		if err := database.DB.Create(finding).Error; err != nil {
			t.Fatal(err)
		}
	}
	addFinding(" CRITICAL ", "", "https://a.example.com/one", 1)
	addFinding("critical", "Unattributed critical", "mantra-discovery", 2)
	addFinding("Critical", "Third critical", "https://a.example.com/three", 3)
	for n := 4; n <= 9; n++ {
		url := fmt.Sprintf("https://a.example.com/%d", n)
		if n == 9 {
			url = "https://orphan.example.com/9"
		}
		addFinding("high", fmt.Sprintf("High %d", n), url, n)
	}
	addFinding("info", "Informational", "https://b.example.com/info", 10)
	addFinding("unscored", "Unknown", "https://b.example.com/unknown", 11)
	if err := database.DB.Create(&models.Vulnerability{
		ProfileID: other.ID, TemplateID: "other", URL: "https://other.example.com/x",
		Severity: "critical", Name: "Other profile",
	}).Error; err != nil {
		t.Fatal(err)
	}

	rec := route(t, http.MethodGet, "/api/profiles/{id}/overview",
		"/api/profiles/"+profile.ID.String()+"/overview", getProfileOverview)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status %d: %s", rec.Code, rec.Body.String())
	}
	var body profileOverview
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Assets.Total != 3 || body.Assets.HTTPObserved != 1 {
		t.Errorf("assets = %+v, want 3 total and 1 observed", body.Assets)
	}
	if body.Profile.LastScanUTC == nil || !body.Profile.LastScanUTC.Equal(scan) ||
		!strings.HasSuffix(body.Profile.LastScanUTC.Format(time.RFC3339), "Z") {
		t.Errorf("last scan = %v, want UTC %v", body.Profile.LastScanUTC, scan)
	}
	if body.LastIdentifiedChangeUTC == nil || !body.LastIdentifiedChangeUTC.Equal(changed) {
		t.Errorf("last identified change = %v, want %v", body.LastIdentifiedChangeUTC, changed)
	}
	wantSeverities := []struct {
		name  string
		count int64
	}{
		{"critical", 3}, {"high", 6}, {"medium", 0},
		{"low", 0}, {"info", 1}, {"unknown", 1},
	}
	for i, want := range wantSeverities {
		if body.FindingSeverities[i].Severity != want.name || body.FindingSeverities[i].Count != want.count {
			t.Errorf("severity[%d] = %+v, want %s=%d", i, body.FindingSeverities[i], want.name, want.count)
		}
	}
	if len(body.PriorityFindings) != 8 {
		t.Fatalf("priority findings = %d, want 8", len(body.PriorityFindings))
	}
	for i, want := range []string{"Third critical", "Unattributed critical", "tpl-1", "High 9", "High 8", "High 7", "High 6", "High 5"} {
		if body.PriorityFindings[i].Name != want {
			t.Errorf("priority[%d] = %q, want %q", i, body.PriorityFindings[i].Name, want)
		}
	}
	if body.PriorityFindings[1].Host != nil {
		t.Errorf("unattributed finding was assigned host %v", *body.PriorityFindings[1].Host)
	}
	if !body.PriorityFindings[0].HasAsset || body.PriorityFindings[3].HasAsset {
		t.Errorf("correlation flags are wrong: critical=%v orphan=%v",
			body.PriorityFindings[0].HasAsset, body.PriorityFindings[3].HasAsset)
	}
}

func TestProfileOverviewEmptyAndMissing(t *testing.T) {
	profile := newAPIEnv(t)
	rec := route(t, http.MethodGet, "/api/profiles/{id}/overview",
		"/api/profiles/"+profile.ID.String()+"/overview", getProfileOverview)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty overview status %d: %s", rec.Code, rec.Body.String())
	}
	var body profileOverview
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Profile.LastScanUTC != nil || body.LastIdentifiedChangeUTC != nil ||
		body.Assets.Total != 0 || body.Assets.HTTPObserved != 0 || len(body.PriorityFindings) != 0 {
		t.Errorf("unexpected empty overview: %+v", body)
	}
	if len(body.FindingSeverities) != 6 {
		t.Errorf("empty severity summary length = %d, want 6", len(body.FindingSeverities))
	}
	missing := route(t, http.MethodGet, "/api/profiles/{id}/overview",
		"/api/profiles/"+uuid.NewString()+"/overview", getProfileOverview)
	if missing.Code != http.StatusNotFound {
		t.Errorf("missing profile status = %d, want 404", missing.Code)
	}
}

func TestProfileOverviewOrdersMixedTimestampPrecision(t *testing.T) {
	profile := newAPIEnv(t)
	for _, name := range []string{"a.example.com", "b.example.com"} {
		if err := database.DB.Create(&models.Subdomain{ProfileID: profile.ID, Domain: name}).Error; err != nil {
			t.Fatal(err)
		}
	}
	second := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	for _, item := range []struct {
		name string
		when time.Time
	}{
		{"a.example.com", second},
		{"b.example.com", second.Add(500 * time.Millisecond)},
	} {
		if err := database.DB.Model(&models.Subdomain{}).
			Where("profile_id = ? AND domain = ?", profile.ID, item.name).
			UpdateColumn("last_changed", item.when).Error; err != nil {
			t.Fatal(err)
		}
	}
	rec := route(t, http.MethodGet, "/api/profiles/{id}/overview",
		"/api/profiles/"+profile.ID.String()+"/overview", getProfileOverview)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status %d: %s", rec.Code, rec.Body.String())
	}
	var body profileOverview
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := second.Add(500 * time.Millisecond)
	if body.LastIdentifiedChangeUTC == nil || !body.LastIdentifiedChangeUTC.Equal(want) {
		t.Errorf("latest change = %v, want %v", body.LastIdentifiedChangeUTC, want)
	}
}
