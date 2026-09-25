package engine

import (
	"bytes"
	"testing"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func TestParseWAFW00FOutput(t *testing.T) {
	tests := []struct {
		name, input, want string
		fails             bool
	}{
		{"named", `[{"url":"https://a.example.com","detected":true,"firewall":"Cloudflare"}]`, "Cloudflare", false},
		{"generic", `[{"url":"https://a.example.com","detected":true,"firewall":"Generic"}]`, "Unknown WAF", false},
		{"none", `[{"url":"https://a.example.com","detected":false,"firewall":"None"}]`, "none", false},
		{"empty", `[]`, "", true},
		{"trailing JSON", `[{"detected":false,"firewall":"None"}] {}`, "", true},
		{"trailing garbage", `[{"detected":false,"firewall":"None"}] junk`, "", true},
		{"trailing whitespace", "[{\"detected\":false,\"firewall\":\"None\"}]\n ", "none", false},
		{"truncated", `[{`, "", true},
		{"inconsistent", `[{"detected":false,"firewall":"Cloudflare"}]`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWAFW00FOutput(bytes.NewBufferString(tt.input))
			if (err != nil) != tt.fails || got != tt.want {
				t.Errorf("parseWAFW00FOutput = %q, %v; want %q, fails=%t", got, err, tt.want, tt.fails)
			}
		})
	}
}

func TestDiffWAFsPreservesLastSuccessAndTouchesOnlyRealChanges(t *testing.T) {
	id := newDiffEnv(t)
	diffSubdomains(&id, []string{"a.example.com", "b.example.com", "child.a.example.com"})
	diffHosts(&id, []models.AliveHost{
		{ProfileID: id, URL: "https://a.example.com", StatusCode: 200},
		{ProfileID: id, URL: "http://b.example.com", StatusCode: 403},
	})
	for _, name := range []string{"a.example.com", "b.example.com", "child.a.example.com"} {
		setAssetChangeTime(t, id, name)
	}
	if got := diffWAFs(&id, []wafObservation{{URL: "https://a.example.com", Name: "none"}}); got != 0 {
		t.Fatalf("initial no-detection counted as a change: %d", got)
	}
	if got := assetChangeTime(t, id, "a.example.com"); !got.Equal(oldChangeTime) {
		t.Fatalf("initial clean probe changed asset timestamp: %v", got)
	}
	if got := diffWAFs(&id, []wafObservation{{URL: "https://a.example.com", Name: "Cloudflare"}}); got != 1 {
		t.Fatalf("first named detection changed %d assets, want 1", got)
	}
	changed := assetChangeTime(t, id, "a.example.com")
	if !changed.After(oldChangeTime) || changed.Location() != time.UTC {
		t.Errorf("asset change timestamp = %v, want fresh UTC", changed)
	}
	if got := diffWAFs(&id, []wafObservation{{URL: "https://a.example.com", Name: "Cloudflare"}}); got != 0 {
		t.Errorf("identical re-sighting changed %d assets", got)
	}
	if got := assetChangeTime(t, id, "a.example.com"); !got.Equal(changed) {
		t.Errorf("identical re-sighting moved timestamp from %v to %v", changed, got)
	}
	// HTTPX metadata refreshes and failed WAF probes must not erase the last
	// successful result. A failed probe contributes no observation to diffWAFs.
	diffHosts(&id, []models.AliveHost{{ProfileID: id, URL: "https://a.example.com", StatusCode: 200}})
	diffWAFs(&id, nil)
	var retained models.AliveHost
	if err := database.DB.Where("profile_id = ? AND url = ?", id, "https://a.example.com").First(&retained).Error; err != nil {
		t.Fatal(err)
	}
	if retained.WAFName == nil || *retained.WAFName != "Cloudflare" {
		t.Errorf("unchanged HTTPX re-sighting erased WAF observation: %v", retained.WAFName)
	}
	if got := diffWAFs(&id, []wafObservation{{URL: "https://a.example.com", Name: "none"}}); got != 1 {
		t.Errorf("WAF disappearance changed %d assets, want 1", got)
	}
	for _, name := range []string{"b.example.com", "child.a.example.com"} {
		if got := assetChangeTime(t, id, name); !got.Equal(oldChangeTime) {
			t.Errorf("unrelated %s timestamp changed to %v", name, got)
		}
	}
	var host models.AliveHost
	if err := database.DB.Where("profile_id = ? AND url = ?", id, "https://a.example.com").First(&host).Error; err != nil {
		t.Fatal(err)
	}
	if host.WAFName == nil || *host.WAFName != "none" {
		t.Errorf("last successful WAF observation = %v, want none", host.WAFName)
	}
}
