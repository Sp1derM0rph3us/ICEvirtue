package api

import (
	"net/http"
	"testing"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func TestMantraSourcesAreNodeScopedAndLegacyRowsStayReadable(t *testing.T) {
	profile := newAPIEnv(t)
	for _, domain := range []string{"a.example.com", "b.example.com"} {
		if err := database.DB.Create(&models.Subdomain{ProfileID: profile.ID, Domain: domain}).Error; err != nil {
			t.Fatal(err)
		}
	}
	rows := []models.SecretFinding{
		{ProfileID: profile.ID, SourceURL: "mantra-discovery", SecretType: "aws", SecretValue: "shared", Engine: "Mantra"},
		{ProfileID: profile.ID, SourceURL: "https://a.example.com/app.js", SecretType: "generic", SecretValue: "shared", Engine: "Mantra"},
		{ProfileID: profile.ID, SourceURL: "https://a.example.com/app.js", SecretType: "aws", SecretValue: "shared", Engine: "SecretHound"},
		{ProfileID: profile.ID, SourceURL: "https://b.example.com/app.js", SecretType: "generic", SecretValue: "other", Engine: "Mantra"},
		{ProfileID: profile.ID, SourceURL: "mantra-discovery", SecretType: "generic", SecretValue: "old-only", Engine: "Mantra"},
	}
	for i := range rows {
		if err := database.DB.Create(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	path := "/api/profiles/" + profile.ID.String() + "/secrets"
	check := func(query string, wantRows int, wantValue, wantSource string) {
		t.Helper()
		page := decodePage[models.SecretFinding](t, route(t, http.MethodGet,
			"/api/profiles/{id}/secrets", path+query, getProfileSecrets), "secrets"+query)
		if page.Page.TotalRows != int64(wantRows) || len(page.Data) != wantRows {
			t.Fatalf("%s: got %d rows, want %d: %+v", query, len(page.Data), wantRows, page.Data)
		}
		if wantRows == 1 && (page.Data[0].SecretValue != wantValue || page.Data[0].SourceURL != wantSource) {
			t.Errorf("%s: got %+v, want %s at %s", query, page.Data[0], wantValue, wantSource)
		}
	}
	check("?host=a.example.com", 1, "shared", "https://a.example.com/app.js")
	check("?host=b.example.com", 1, "other", "https://b.example.com/app.js")
	check("?host=c.example.com", 0, "", "")
	check("", 3, "", "")

	all := decodePage[models.SecretFinding](t, route(t, http.MethodGet,
		"/api/profiles/{id}/secrets", path, getProfileSecrets), "secrets")
	var legacyFound bool
	for _, row := range all.Data {
		if row.SourceURL == "mantra-discovery" {
			legacyFound = row.SecretValue == "old-only"
		}
	}
	if !legacyFound {
		t.Errorf("historical unattributed finding missing: %+v", all.Data)
	}

	nodes := decodePage[subdomainRow](t, route(t, http.MethodGet,
		"/api/profiles/{id}/subdomains", "/api/profiles/"+profile.ID.String()+"/subdomains", getProfileSubdomains), "subdomains")
	if len(nodes.Data) != 2 {
		t.Fatalf("got %d nodes, want two: %+v", len(nodes.Data), nodes.Data)
	}
	for _, node := range nodes.Data {
		if node.SecretCount != 1 {
			t.Errorf("%s shows %d credentials, want one visible finding", node.Domain, node.SecretCount)
		}
	}
}

func TestArchivedSecretIsAttributedToOriginalHostWithEvidence(t *testing.T) {
	profile := newAPIEnv(t)
	source := "https://a.example.com/old.js"
	archive := "https://web.archive.org/web/20200101000000/" + source
	if err := database.DB.Create(&models.Subdomain{ProfileID: profile.ID, Domain: "a.example.com"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Create(&models.SecretFinding{
		ProfileID: profile.ID, SourceURL: source, ArchiveURL: archive,
		SecretType: "aws", SecretValue: "archived-value", Engine: "SecretHound",
	}).Error; err != nil {
		t.Fatal(err)
	}
	path := "/api/profiles/" + profile.ID.String() + "/secrets?host=a.example.com"
	page := decodePage[models.SecretFinding](t, route(t, http.MethodGet,
		"/api/profiles/{id}/secrets", path, getProfileSecrets), "archived secret")
	if len(page.Data) != 1 || page.Data[0].SourceURL != source || page.Data[0].ArchiveURL != archive || page.Data[0].SeenLive {
		t.Fatalf("archived evidence not attributed to original node: %+v", page.Data)
	}
}
