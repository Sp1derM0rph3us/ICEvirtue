package engine

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// These tests cover the correlation key on the write path. Three mechanisms keep it
// populated and each is checked here: the BeforeSave hook on insert, the explicit
// repair when a row is seen again (hooks do not fire for Update), and the fact that
// a value carrying no host is stored as SQL NULL rather than as an empty string.

// newDiffEnv gives the test an isolated database and one profile. It is deliberately
// lighter than newPipelineEnv: the diff functions never execute a tool, so there is
// no reason to build a stub PATH or move the engine's flags around.
func newDiffEnv(t *testing.T) uuid.UUID {
	t.Helper()

	prevDB := database.DB
	t.Cleanup(func() { database.DB = prevDB })

	if err := database.InitDatabase(filepath.Join(t.TempDir(), "diff.db")); err != nil {
		t.Fatalf("InitDatabase: %v", err)
	}

	profile := &models.Profile{Domain: "example.com", Mode: "full", Schedule: "@every 24h", Enabled: true}
	if err := database.DB.Create(profile).Error; err != nil {
		t.Fatalf("creating profile: %v", err)
	}
	return profile.ID
}

// hostOf reads the raw host column so the test observes what is actually stored,
// including the difference between NULL and "" — which is the distinction the whole
// design rests on, so the helper has to be able to see it. sql.NullString is what
// makes that possible; scanning into a plain string or a *string through GORM's
// slice path collapses NULL into an error instead of reporting it.
func hostOf(t *testing.T, table string, where string, args ...interface{}) (value string, isNull bool) {
	t.Helper()

	var host sql.NullString
	row := database.DB.Raw("SELECT host FROM "+table+" WHERE "+where, args...).Row()
	if err := row.Scan(&host); err != nil {
		t.Fatalf("reading %s.host where %s: %v", table, where, err)
	}
	return host.String, !host.Valid
}

func TestInsertPopulatesTheCorrelationKey(t *testing.T) {
	id := newDiffEnv(t)

	diffSubdomains(&id, []string{"A.Example.COM.", "sub.a.example.com", "1.2.3.4"})
	diffHosts(&id, []models.AliveHost{{ProfileID: id, URL: "https://a.example.com:8443", StatusCode: 200}})
	diffVulns(&id, []models.Vulnerability{{
		ProfileID: id, TemplateID: "t1", URL: "https://a.example.com/wp-login.php", Severity: "high",
	}})
	diffDirectories(&id, []models.DirectoryFinding{{
		ProfileID: id, SubdomainURL: "https://a.example.com", DirURL: "https://a.example.com/admin", StatusCode: 403,
	}})
	diffSecrets(&id, []models.SecretFinding{{
		ProfileID: id, SourceURL: "https://a.example.com/static/app.js?v=2", SecretType: "aws", SecretValue: "AKIA1",
	}})

	cases := []struct {
		table, where string
		arg          interface{}
		want         string
	}{
		{"subdomains", "domain = ?", "A.Example.COM.", "a.example.com"},
		{"subdomains", "domain = ?", "sub.a.example.com", "sub.a.example.com"},
		{"subdomains", "domain = ?", "1.2.3.4", "1.2.3.4"},
		{"alive_hosts", "url = ?", "https://a.example.com:8443", "a.example.com"},
		{"vulnerabilities", "template_id = ?", "t1", "a.example.com"},
		{"directory_findings", "dir_url = ?", "https://a.example.com/admin", "a.example.com"},
		{"secret_findings", "secret_value = ?", "AKIA1", "a.example.com"},
	}
	for _, c := range cases {
		got, isNull := hostOf(t, c.table, c.where, c.arg)
		if isNull {
			t.Errorf("%s (%s=%v): host is NULL, want %q", c.table, c.where, c.arg, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("%s (%s=%v): host = %q, want %q", c.table, c.where, c.arg, got, c.want)
		}
	}

	// The whole point of the exercise: every one of those findings keys to the same
	// host as the subdomain row, so the correlation is an equality join rather than a
	// substring scan — and the parent does not absorb the child.
	var n int64
	database.DB.Raw(`SELECT COUNT(*) FROM vulnerabilities v
	                 JOIN subdomains s ON s.profile_id = v.profile_id AND s.host = v.host
	                 WHERE s.domain = ?`, "A.Example.COM.").Scan(&n)
	if n != 1 {
		t.Errorf("the vulnerability joined to a.example.com %d time(s), want 1", n)
	}
	database.DB.Raw(`SELECT COUNT(*) FROM vulnerabilities v
	                 JOIN subdomains s ON s.profile_id = v.profile_id AND s.host = v.host
	                 WHERE s.domain = ?`, "sub.a.example.com").Scan(&n)
	if n != 0 {
		t.Errorf("the parent's vulnerability leaked onto the child %d time(s), want 0", n)
	}
}

// TestReSightingRepairsTheCorrelationKey is the reason the diff* update branches
// write host explicitly. GORM hooks do not fire for Update, so without it a row
// inserted before this feature existed would keep a NULL key forever unless the
// one-time backfill happened to reach it.
func TestReSightingRepairsTheCorrelationKey(t *testing.T) {
	id := newDiffEnv(t)

	// Seed a row the way a pre-migration database holds it: correct domain, no key.
	// Raw SQL on purpose — going through GORM would fire the hook and populate it,
	// which is the state this test needs to NOT start from.
	if err := database.DB.Exec(
		`INSERT INTO subdomains (profile_id, domain, host, first_seen, last_seen)
		 VALUES (?, ?, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, id, "a.example.com").Error; err != nil {
		t.Fatalf("seeding a pre-migration row: %v", err)
	}
	if _, isNull := hostOf(t, "subdomains", "domain = ?", "a.example.com"); !isNull {
		t.Fatal("the seeded row already has a host; this test cannot prove the repair")
	}

	// Seeing the same name again must take the update branch, not create a new row.
	if newCount := diffSubdomains(&id, []string{"a.example.com"}); newCount != 0 {
		t.Errorf("diffSubdomains reported %d new row(s) for a name it had already seen, want 0", newCount)
	}

	got, isNull := hostOf(t, "subdomains", "domain = ?", "a.example.com")
	if isNull {
		t.Fatal("host is still NULL after the row was seen again; the update branch did not repair it")
	}
	if got != "a.example.com" {
		t.Errorf("repaired host = %q, want %q", got, "a.example.com")
	}
}

// TestUncorrelatableFindingIsStoredAsNull is what makes the failure mode safe. A
// value with no usable host must be NULL, because NULL never equals NULL and so
// cannot be joined — whereas "" would join every such row to every other one.
func TestUncorrelatableFindingIsStoredAsNull(t *testing.T) {
	id := newDiffEnv(t)

	// mantra reports its findings against the literal string "mantra-discovery".
	diffSecrets(&id, []models.SecretFinding{
		{ProfileID: id, SourceURL: "mantra-discovery", SecretType: "aws", SecretValue: "AKIA1"},
		{ProfileID: id, SourceURL: "mantra-discovery", SecretType: "stripe", SecretValue: "sk_live_2"},
	})
	// A subdomain that also fails to yield a host, so there is something for a
	// mistakenly-empty-string key to join against.
	diffSubdomains(&id, []string{"localhost"})

	if _, isNull := hostOf(t, "secret_findings", "secret_value = ?", "AKIA1"); !isNull {
		t.Error("a secret with no usable source host was not stored as NULL")
	}
	if _, isNull := hostOf(t, "subdomains", "domain = ?", "localhost"); !isNull {
		t.Error("a dotless subdomain was not stored as NULL")
	}

	var n int64
	database.DB.Raw(`SELECT COUNT(*) FROM secret_findings c
	                 JOIN subdomains s ON s.profile_id = c.profile_id AND s.host = c.host`).Scan(&n)
	if n != 0 {
		t.Errorf("%d uncorrelatable secret(s) joined to a subdomain; NULL must never match", n)
	}

	// And they are still stored and still visible profile-wide — never dropped.
	database.DB.Raw("SELECT COUNT(*) FROM secret_findings WHERE profile_id = ?", id).Scan(&n)
	if n != 2 {
		t.Errorf("secret_findings holds %d row(s), want 2: a finding must be kept even when it cannot be attributed", n)
	}
}
