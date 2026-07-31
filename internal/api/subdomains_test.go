package api

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// seedCorrelated builds a profile whose findings exercise the correlation rules:
// a parent name, a child of it, the apex, an IP, and a name with nothing on it.
func seedCorrelated(t *testing.T) uuid.UUID {
	t.Helper()

	profile := newAPIEnv(t)
	id := profile.ID

	create := func(what string, row interface{}) {
		t.Helper()
		if err := database.DB.Create(row).Error; err != nil {
			t.Fatalf("seeding %s: %v", what, err)
		}
	}

	for _, name := range []string{"example.com", "a.example.com", "sub.a.example.com", "1.2.3.4", "quiet.example.com"} {
		create("subdomain "+name, &models.Subdomain{ProfileID: id, Domain: name})
	}

	// a.example.com: 200, two vulns (one info), three dirs, one secret.
	create("host a", &models.AliveHost{ProfileID: id, URL: "https://a.example.com", StatusCode: 200})
	create("vuln a1", &models.Vulnerability{ProfileID: id, TemplateID: "t1", URL: "https://a.example.com/x", Severity: "critical"})
	create("vuln a2", &models.Vulnerability{ProfileID: id, TemplateID: "t2", URL: "https://a.example.com/y", Severity: "info"})
	for i := range 3 {
		create("dir a", &models.DirectoryFinding{
			ProfileID: id, SubdomainURL: "https://a.example.com",
			DirURL: fmt.Sprintf("https://a.example.com/d%d", i), StatusCode: 200,
		})
	}
	create("secret a", &models.SecretFinding{
		ProfileID: id, SourceURL: "https://a.example.com/app.js", SecretType: "aws", SecretValue: "AKIA1",
	})

	// sub.a.example.com: 403, one info vuln, no dirs, no secrets.
	create("host sub", &models.AliveHost{ProfileID: id, URL: "https://sub.a.example.com", StatusCode: 403})
	create("vuln sub", &models.Vulnerability{ProfileID: id, TemplateID: "t3", URL: "https://sub.a.example.com/z", Severity: "info"})

	// 1.2.3.4: alive, nothing else.
	create("host ip", &models.AliveHost{ProfileID: id, URL: "http://1.2.3.4", StatusCode: 200})

	// A secret mantra could not attribute. It must count towards nothing.
	create("secret orphan", &models.SecretFinding{
		ProfileID: id, SourceURL: "mantra-discovery", SecretType: "generic", SecretValue: "orphan",
	})

	return id
}

func rowsByDomain(page ListResponse[subdomainRow]) map[string]subdomainRow {
	out := make(map[string]subdomainRow, len(page.Data))
	for _, r := range page.Data {
		out[r.Domain] = r
	}
	return out
}

// TestPerRowCountsUseExactHostMatching is the correctness core of the change. Under the
// old substring correlation the apex absorbed every finding in the profile and the
// parent absorbed its child's, because a parent name is a substring of its children.
func TestPerRowCountsUseExactHostMatching(t *testing.T) {
	id := seedCorrelated(t)
	rows := rowsByDomain(getSubdomainPage(t, id, "?size=500"))

	cases := []struct {
		domain               string
		vulns, dirs, secrets int
		status               *int
	}{
		{"a.example.com", 2, 3, 1, intPtr(200)},
		{"sub.a.example.com", 1, 0, 0, intPtr(403)},
		// The apex was enumerated but nothing was ever observed on it. Substring
		// matching reported the whole profile here.
		{"example.com", 0, 0, 0, nil},
		{"1.2.3.4", 0, 0, 0, intPtr(200)},
		// Never probed, so no status: this is what the dashboard renders as DEAD.
		{"quiet.example.com", 0, 0, 0, nil},
	}

	for _, c := range cases {
		row, ok := rows[c.domain]
		if !ok {
			t.Errorf("%s is missing from the page", c.domain)
			continue
		}
		if row.VulnCount != c.vulns || row.DirCount != c.dirs || row.SecretCount != c.secrets {
			t.Errorf("%s: counts = %dv/%dd/%dc, want %dv/%dd/%dc",
				c.domain, row.VulnCount, row.DirCount, row.SecretCount, c.vulns, c.dirs, c.secrets)
		}
		switch {
		case c.status == nil && row.StatusCode != nil:
			t.Errorf("%s: status = %d, want null so the UI shows DEAD", c.domain, *row.StatusCode)
		case c.status != nil && row.StatusCode == nil:
			t.Errorf("%s: status is null, want %d", c.domain, *c.status)
		case c.status != nil && *row.StatusCode != *c.status:
			t.Errorf("%s: status = %d, want %d", c.domain, *row.StatusCode, *c.status)
		}
	}
}

func intPtr(v int) *int { return &v }

// TestStatusPrefersTheMostAliveHost covers the MIN rule. httpx can report both an
// http:// and an https:// URL for one name, and the badge has to pick deterministically.
func TestStatusPrefersTheMostAliveHost(t *testing.T) {
	profile := newAPIEnv(t)
	id := profile.ID

	database.DB.Create(&models.Subdomain{ProfileID: id, Domain: "a.example.com"})
	// Inserted worst-first, so a rule that took the first row would answer 500.
	database.DB.Create(&models.AliveHost{ProfileID: id, URL: "http://a.example.com", StatusCode: 500})
	database.DB.Create(&models.AliveHost{ProfileID: id, URL: "https://a.example.com", StatusCode: 200})

	rows := rowsByDomain(getSubdomainPage(t, id, ""))
	row := rows["a.example.com"]
	if row.StatusCode == nil || *row.StatusCode != 200 {
		t.Errorf("status = %v, want 200: MIN must prefer the most alive of a host's URLs", row.StatusCode)
	}

	// And the filter reads the same expression, so the badge and the pill agree.
	page := getSubdomainPage(t, id, "?filter=status-2xx-3xx")
	if page.Page.TotalRows != 1 {
		t.Errorf("the 2xx/3xx filter matched %d row(s), want 1 — the badge and the filter disagree", page.Page.TotalRows)
	}
}

// TestSubdomainFiltersRunInSQL checks each pill against the whole result set. Applied on
// the client they would have filtered only the fetched page, which looks right and is
// wrong.
func TestSubdomainFiltersRunInSQL(t *testing.T) {
	id := seedCorrelated(t)

	cases := []struct {
		filter string
		want   int64
		note   string
	}{
		{"", 5, "no filter"},
		{"ip", 1, "only 1.2.3.4"},
		{"subdomain", 4, "everything that is not an address"},
		{"vuln-critical", 1, "only a.example.com has a vuln above info"},
		{"vuln-info", 4, "no vulns at all, or nothing beyond info"},
		{"secrets", 1, "the orphaned secret counts towards nobody"},
		{"status-2xx-3xx", 2, "a.example.com and 1.2.3.4"},
		{"status-403", 1, "sub.a.example.com"},
		{"status-other", 0, "a DEAD node must not match Others"},
		// An unknown filter degrades to unfiltered, visibly.
		{"bogus", 5, "unknown filter is dropped"},
	}

	for _, c := range cases {
		page := getSubdomainPage(t, id, "?filter="+c.filter+"&size=500")
		if page.Page.TotalRows != c.want {
			t.Errorf("filter=%q matched %d row(s), want %d (%s)", c.filter, page.Page.TotalRows, c.want, c.note)
		}
		if int64(len(page.Data)) != c.want {
			t.Errorf("filter=%q returned %d row(s) but reported %d", c.filter, len(page.Data), page.Page.TotalRows)
		}

		wantEcho := c.filter
		if c.filter == "bogus" {
			wantEcho = ""
		}
		if page.Page.Filter != wantEcho {
			t.Errorf("filter=%q was echoed as %q, want %q", c.filter, page.Page.Filter, wantEcho)
		}
	}
}

// TestSortByFindingsVolumeOrdersByTheTotal covers the one sort that cannot be
// index-ordered, and that the pages still partition the set.
func TestSortByFindingsVolumeOrdersByTheTotal(t *testing.T) {
	id := seedCorrelated(t)

	desc := getSubdomainPage(t, id, "?sort=findings-desc&size=500")
	if len(desc.Data) != 5 {
		t.Fatalf("got %d rows, want 5", len(desc.Data))
	}
	if desc.Data[0].Domain != "a.example.com" {
		t.Errorf("first row is %s, want a.example.com with 6 findings", desc.Data[0].Domain)
	}

	total := func(r subdomainRow) int { return r.VulnCount + r.DirCount + r.SecretCount }
	for i := 1; i < len(desc.Data); i++ {
		if total(desc.Data[i-1]) < total(desc.Data[i]) {
			t.Errorf("findings-desc is not monotonic at %d: %d then %d",
				i, total(desc.Data[i-1]), total(desc.Data[i]))
		}
	}

	asc := getSubdomainPage(t, id, "?sort=findings-asc&size=500")
	if total(asc.Data[0]) > total(asc.Data[len(asc.Data)-1]) {
		t.Error("findings-asc is ordered the wrong way round")
	}
}

// TestFindingEndpointsScopeToOneHost covers the node detail view, which used to be
// three client-side filter passes over the whole dataset.
func TestFindingEndpointsScopeToOneHost(t *testing.T) {
	id := seedCorrelated(t)

	vulns := decodePage[models.Vulnerability](t, route(t, "GET", "/api/profiles/{id}/vulnerabilities",
		"/api/profiles/"+id.String()+"/vulnerabilities?host=a.example.com", getProfileVulnerabilities), "vulns")
	if vulns.Page.TotalRows != 2 {
		t.Errorf("a.example.com has %d vuln(s), want 2", vulns.Page.TotalRows)
	}
	if vulns.Page.Host != "a.example.com" {
		t.Errorf("the envelope echoed host %q", vulns.Page.Host)
	}

	// The child's finding must not appear under the parent.
	for _, v := range vulns.Data {
		if v.TemplateID == "t3" {
			t.Error("the child's vulnerability was returned under the parent host")
		}
	}

	dirs := decodePage[models.DirectoryFinding](t, route(t, "GET", "/api/profiles/{id}/directories",
		"/api/profiles/"+id.String()+"/directories?host=a.example.com", getProfileDirectories), "dirs")
	if dirs.Page.TotalRows != 3 {
		t.Errorf("a.example.com has %d dir(s), want 3", dirs.Page.TotalRows)
	}

	// A host scope that normalizes to nothing must return an empty page, never the
	// rows whose host is NULL.
	orphan := decodePage[models.SecretFinding](t, route(t, "GET", "/api/profiles/{id}/secrets",
		"/api/profiles/"+id.String()+"/secrets?host=mantra-discovery", getProfileSecrets), "secrets")
	if orphan.Page.TotalRows != 0 || len(orphan.Data) != 0 {
		t.Errorf("an unresolvable host scope returned %d row(s); it must never match the NULL-host rows", orphan.Page.TotalRows)
	}

	// Unscoped, that secret is still there. A finding that cannot be attributed is
	// still a finding.
	all := decodePage[models.SecretFinding](t, route(t, "GET", "/api/profiles/{id}/secrets",
		"/api/profiles/"+id.String()+"/secrets", getProfileSecrets), "secrets")
	if all.Page.TotalRows != 2 {
		t.Errorf("the profile has %d secret(s), want 2 including the unattributable one", all.Page.TotalRows)
	}
}

// TestVulnerabilitiesSortBySeverityRank guards against the alphabetical ordering that
// would put info third, between medium and low.
func TestVulnerabilitiesSortBySeverityRank(t *testing.T) {
	profile := newAPIEnv(t)
	id := profile.ID

	for i, sev := range []string{"info", "low", "critical", "medium", "high"} {
		database.DB.Create(&models.Vulnerability{
			ProfileID: id, TemplateID: fmt.Sprintf("t%d", i),
			URL: fmt.Sprintf("https://a.example.com/%d", i), Severity: sev,
		})
	}

	page := decodePage[models.Vulnerability](t, route(t, "GET", "/api/profiles/{id}/vulnerabilities",
		"/api/profiles/"+id.String()+"/vulnerabilities", getProfileVulnerabilities), "vulns")

	var got []string
	for _, v := range page.Data {
		got = append(got, v.Severity)
	}
	want := []string{"critical", "high", "medium", "low", "info"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("severity order = %v, want %v", got, want)
		}
	}
}

// TestPerRowCountsAreCapped covers the bound on the per-row counts.
//
// The count is O(matching rows), so before the cap a single host carrying tens of
// thousands of findings made whichever page it landed on an order of magnitude slower
// than its neighbours — measured at 1466ms against 11ms for the page next to it.
func TestPerRowCountsAreCapped(t *testing.T) {
	profile := newAPIEnv(t)
	id := profile.ID
	host := "hot.example.com"

	database.DB.Create(&models.Subdomain{ProfileID: id, Domain: host})

	// Just over the cap, so the cap is what stops the count rather than the data.
	rows := make([]models.DirectoryFinding, 0, countCap+20)
	for i := range countCap + 20 {
		rows = append(rows, models.DirectoryFinding{
			ProfileID: id, SubdomainURL: "https://" + host,
			DirURL: fmt.Sprintf("https://%s/d%05d", host, i), StatusCode: 200,
		})
	}
	if err := database.DB.CreateInBatches(rows, 500).Error; err != nil {
		t.Fatalf("seeding directories: %v", err)
	}

	page := getSubdomainPage(t, id, "")
	row := rowsByDomain(page)[host]
	if row.DirCount != countCap {
		t.Errorf("dir_count = %d, want it capped at %d", row.DirCount, countCap)
	}

	// The exact total is still exact where it matters: the node's own tab.
	dirs := decodePage[models.DirectoryFinding](t, route(t, "GET", "/api/profiles/{id}/directories",
		"/api/profiles/"+id.String()+"/directories?host="+host+"&size=1", getProfileDirectories), "dirs")
	if dirs.Page.TotalRows != int64(countCap+20) {
		t.Errorf("the node's own tab reported %d rows, want the exact %d", dirs.Page.TotalRows, countCap+20)
	}
}

// TestCountsBelowTheCapAreExact guards against the cap being applied where it is not
// needed, which would make every badge read as an approximation.
func TestCountsBelowTheCapAreExact(t *testing.T) {
	id := seedCorrelated(t)
	row := rowsByDomain(getSubdomainPage(t, id, "?size=500"))["a.example.com"]
	if row.DirCount != 3 || row.VulnCount != 2 || row.SecretCount != 1 {
		t.Errorf("counts below the cap must be exact, got %dv/%dd/%dc", row.VulnCount, row.DirCount, row.SecretCount)
	}
}
