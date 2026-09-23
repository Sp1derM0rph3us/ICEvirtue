package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func TestWAFSummariesAreProfileAndHostScoped(t *testing.T) {
	profile := newAPIEnv(t)
	other := &models.Profile{Domain: "other.example.com"}
	if err := database.DB.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	value := func(s string) *string { return &s }
	for _, row := range []models.AliveHost{
		{ProfileID: profile.ID, URL: "http://a.example.com", WAFName: value("Cloudflare")},
		{ProfileID: profile.ID, URL: "https://a.example.com", WAFName: value("Cloudflare")},
		{ProfileID: profile.ID, URL: "https://child.a.example.com", WAFName: value("Unknown WAF")},
		{ProfileID: profile.ID, URL: "https://b.example.com", WAFName: value("none")},
		{ProfileID: profile.ID, URL: "https://c.example.com"},
		{ProfileID: other.ID, URL: "https://a.example.com", WAFName: value("Akamai")},
	} {
		if err := database.DB.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	check := func(host string, names []string, scanned bool) {
		t.Helper()
		rec := route(t, http.MethodGet, "/api/profiles/{id}/wafs",
			"/api/profiles/"+profile.ID.String()+"/wafs?host="+host, getProfileWAFs)
		if rec.Code != http.StatusOK {
			t.Fatalf("node WAF status = %d: %s", rec.Code, rec.Body.String())
		}
		var body nodeWAFs
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(body.Names, names) || body.Scanned != scanned {
			t.Errorf("host %s: %+v, want names=%v scanned=%t", host, body, names, scanned)
		}
	}
	check("a.example.com", []string{"Cloudflare"}, true)
	check("child.a.example.com", []string{"Unknown WAF"}, true)
	check("b.example.com", []string{}, true)
	check("c.example.com", []string{}, false)
	check("missing.example.com", []string{}, false)

	rec := route(t, http.MethodGet, "/api/profiles/{id}/overview",
		"/api/profiles/"+profile.ID.String()+"/overview", getProfileOverview)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status = %d: %s", rec.Code, rec.Body.String())
	}
	var overview profileOverview
	if err := json.Unmarshal(rec.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if want := []string{"Cloudflare", "Unknown WAF"}; !reflect.DeepEqual(overview.DetectedWAFs, want) {
		t.Errorf("overview WAFs = %v, want %v", overview.DetectedWAFs, want)
	}
}
