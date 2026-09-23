package database

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// newMigrateEnv opens an isolated database and returns a profile id to hang rows off.
func newMigrateEnv(t *testing.T) uuid.UUID {
	t.Helper()

	prevDB := DB
	t.Cleanup(func() { DB = prevDB })

	if err := InitDatabase(filepath.Join(t.TempDir(), "migrate.db")); err != nil {
		t.Fatalf("InitDatabase: %v", err)
	}

	id := uuid.New()
	if err := DB.Create(&models.Profile{ID: id, Domain: "example.com", Enabled: true}).Error; err != nil {
		t.Fatalf("creating profile: %v", err)
	}
	return id
}

// seedUnmigrated inserts rows the way a database written before this feature holds
// them: real source values, host NULL. Raw SQL is required — going through GORM would
// fire the BeforeSave hook and populate host, which is the state these tests must not
// start from.
func seedUnmigrated(t *testing.T, id uuid.UUID, subdomains, vulnURLs, secretSources []string) {
	t.Helper()

	for _, d := range subdomains {
		if err := DB.Exec(`INSERT INTO subdomains (profile_id, domain, host, first_seen, last_seen)
		                   VALUES (?, ?, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, id, d).Error; err != nil {
			t.Fatalf("seeding subdomain %s: %v", d, err)
		}
	}
	for i, u := range vulnURLs {
		if err := DB.Exec(`INSERT INTO vulnerabilities (profile_id, template_id, url, host, severity, first_seen, last_seen)
		                   VALUES (?, ?, ?, NULL, 'info', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			id, fmt.Sprintf("tpl-%d", i), u).Error; err != nil {
			t.Fatalf("seeding vulnerability %s: %v", u, err)
		}
	}
	for i, s := range secretSources {
		if err := DB.Exec(`INSERT INTO secret_findings (profile_id, source_url, host, secret_type, secret_value, first_seen, last_seen)
		                   VALUES (?, ?, NULL, 'aws', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			id, s, fmt.Sprintf("AKIA%d", i)).Error; err != nil {
			t.Fatalf("seeding secret %s: %v", s, err)
		}
	}
}

func countHosts(t *testing.T, table string) (filled, null int) {
	t.Helper()

	var f, n int64
	if err := DB.Raw("SELECT COUNT(*) FROM " + table + " WHERE host IS NOT NULL").Scan(&f).Error; err != nil {
		t.Fatalf("counting %s: %v", table, err)
	}
	if err := DB.Raw("SELECT COUNT(*) FROM " + table + " WHERE host IS NULL").Scan(&n).Error; err != nil {
		t.Fatalf("counting %s: %v", table, err)
	}
	return int(f), int(n)
}

func hostFor(t *testing.T, table, where string, arg interface{}) (string, bool) {
	t.Helper()

	var host sql.NullString
	if err := DB.Raw("SELECT host FROM "+table+" WHERE "+where, arg).Row().Scan(&host); err != nil {
		t.Fatalf("reading %s.host: %v", table, err)
	}
	return host.String, !host.Valid
}

func TestRunDataMigrationsBackfillsEveryTable(t *testing.T) {
	id := newMigrateEnv(t)
	seedUnmigrated(t,
		id,
		[]string{"A.Example.COM.", "sub.a.example.com", "1.2.3.4", "localhost"},
		[]string{"https://a.example.com/wp-login.php", "https://sub.a.example.com:8443/x"},
		[]string{"https://a.example.com/app.js", "mantra-discovery"},
	)

	if err := RunDataMigrations(); err != nil {
		t.Fatalf("RunDataMigrations: %v", err)
	}

	// Normalized, not copied verbatim.
	for _, c := range []struct {
		table, where string
		arg          interface{}
		want         string
	}{
		{"subdomains", "domain = ?", "A.Example.COM.", "a.example.com"},
		{"subdomains", "domain = ?", "1.2.3.4", "1.2.3.4"},
		{"vulnerabilities", "template_id = ?", "tpl-0", "a.example.com"},
		{"vulnerabilities", "template_id = ?", "tpl-1", "sub.a.example.com"},
		{"secret_findings", "secret_value = ?", "AKIA0", "a.example.com"},
	} {
		got, isNull := hostFor(t, c.table, c.where, c.arg)
		if isNull {
			t.Errorf("%s where %s=%v: host still NULL, want %q", c.table, c.where, c.arg, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("%s where %s=%v: host = %q, want %q", c.table, c.where, c.arg, got, c.want)
		}
	}

	// The two values with no usable host stay NULL rather than becoming "".
	if _, isNull := hostFor(t, "subdomains", "domain = ?", "localhost"); !isNull {
		t.Error("a dotless name was given a host; it must stay NULL so nothing joins to it")
	}
	if _, isNull := hostFor(t, "secret_findings", "secret_value = ?", "AKIA1"); !isNull {
		t.Error("mantra's placeholder was given a host; it must stay NULL")
	}

	if filled, null := countHosts(t, "subdomains"); filled != 3 || null != 1 {
		t.Errorf("subdomains: %d filled / %d null, want 3 / 1", filled, null)
	}
	if filled, null := countHosts(t, "secret_findings"); filled != 1 || null != 1 {
		t.Errorf("secret_findings: %d filled / %d null, want 1 / 1", filled, null)
	}

	// No row is lost. A finding that cannot be attributed is still a finding.
	var total int64
	DB.Raw("SELECT COUNT(*) FROM subdomains").Scan(&total)
	if total != 4 {
		t.Errorf("subdomains holds %d row(s) after the migration, want 4", total)
	}
}

// TestRunDataMigrationsIsIdempotent is the property that makes it safe to call on
// every start. The second run must do nothing at all — and in particular must not
// revisit the rows that legitimately ended up NULL.
func TestRunDataMigrationsIsIdempotent(t *testing.T) {
	id := newMigrateEnv(t)
	seedUnmigrated(t, id, []string{"a.example.com", "localhost"}, nil, nil)

	if err := RunDataMigrations(); err != nil {
		t.Fatalf("first run: %v", err)
	}
	firstFilled, firstNull := countHosts(t, "subdomains")

	if err := RunDataMigrations(); err != nil {
		t.Fatalf("second run: %v", err)
	}
	secondFilled, secondNull := countHosts(t, "subdomains")

	if firstFilled != secondFilled || firstNull != secondNull {
		t.Errorf("second run changed the data: %d/%d became %d/%d", firstFilled, firstNull, secondFilled, secondNull)
	}

	// Exactly one ledger row, so the marker is what short-circuits the second run.
	var markers int64
	DB.Model(&models.SchemaMigration{}).Where("version = ?", hostCorrelationV1).Count(&markers)
	if markers != 1 {
		t.Errorf("the migration ledger holds %d row(s) for %s, want 1", markers, hostCorrelationV1)
	}
}

func TestTimestampMigrationPreservesInstantsAndIsIdempotent(t *testing.T) {
	id := newMigrateEnv(t)
	legacyScan := "2026-03-01T10:30:00-03:00"
	legacyChange := "2026-03-01T09:15:00-03:00"
	if err := DB.Exec("UPDATE profiles SET last_scan = ?, last_scan_status = 'completed' WHERE id = ?", legacyScan, id).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Exec(`INSERT INTO subdomains (profile_id, domain, first_seen, last_seen, last_changed)
		VALUES (?, 'a.example.com', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)`, id, legacyChange).Error; err != nil {
		t.Fatal(err)
	}
	never := &models.Profile{Domain: "never.example.com"}
	if err := DB.Create(never).Error; err != nil {
		t.Fatal(err)
	}

	if err := RunDataMigrations(); err != nil {
		t.Fatalf("first migration: %v", err)
	}
	var profile models.Profile
	if err := DB.First(&profile, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	wantScan := time.Date(2026, 3, 1, 13, 30, 0, 0, time.UTC)
	if !profile.LastScan.Equal(wantScan) || profile.LastScan.Location() != time.UTC {
		t.Errorf("migrated scan = %v, want %v in UTC", profile.LastScan, wantScan)
	}
	var sub models.Subdomain
	if err := DB.First(&sub, "profile_id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	wantChange := time.Date(2026, 3, 1, 12, 15, 0, 0, time.UTC)
	if !sub.LastChanged.Equal(wantChange) || sub.LastChanged.Location() != time.UTC {
		t.Errorf("migrated change = %v, want %v in UTC", sub.LastChanged, wantChange)
	}
	var neverRow models.Profile
	if err := DB.First(&neverRow, "id = ?", never.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !neverRow.LastScan.IsZero() {
		t.Errorf("never-scanned profile gained timestamp %v", neverRow.LastScan)
	}
	var firstScan, firstChange string
	DB.Raw("SELECT last_scan FROM profiles WHERE id = ?", id).Scan(&firstScan)
	DB.Raw("SELECT last_changed FROM subdomains WHERE id = ?", sub.ID).Scan(&firstChange)
	if !strings.HasSuffix(firstScan, "Z") || !strings.HasSuffix(firstChange, "Z") {
		t.Errorf("timestamps were not stored with UTC offsets: scan=%q change=%q", firstScan, firstChange)
	}
	if err := RunDataMigrations(); err != nil {
		t.Fatalf("second migration: %v", err)
	}
	var secondScan, secondChange string
	DB.Raw("SELECT last_scan FROM profiles WHERE id = ?", id).Scan(&secondScan)
	DB.Raw("SELECT last_changed FROM subdomains WHERE id = ?", sub.ID).Scan(&secondChange)
	if firstScan != secondScan || firstChange != secondChange {
		t.Errorf("second migration rewrote timestamps: %q/%q -> %q/%q", firstScan, firstChange, secondScan, secondChange)
	}
}

// TestRunDataMigrationsCrossesBatchBoundaries exercises the keyset walk with more
// rows than one batch. A cursor bug here would either drop rows or loop forever, and
// both are invisible at small sizes.
func TestRunDataMigrationsCrossesBatchBoundaries(t *testing.T) {
	id := newMigrateEnv(t)

	const total = backfillBatch*2 + 37
	names := make([]string, 0, total)
	for i := range total {
		// Every fourth row carries no usable host, so the NULLs are scattered across
		// batch boundaries rather than clustered at the end.
		if i%4 == 3 {
			names = append(names, fmt.Sprintf("host-%04d", i)) // dotless, unresolvable
		} else {
			names = append(names, fmt.Sprintf("host-%04d.example.com", i))
		}
	}
	seedUnmigrated(t, id, names, nil, nil)

	if err := RunDataMigrations(); err != nil {
		t.Fatalf("RunDataMigrations: %v", err)
	}

	wantNull := total / 4
	if total%4 > 3 {
		wantNull++
	}
	filled, null := countHosts(t, "subdomains")
	if filled+null != total {
		t.Fatalf("subdomains holds %d row(s), want %d — the keyset walk lost rows", filled+null, total)
	}
	if null != wantNull {
		t.Errorf("%d row(s) left NULL, want %d", null, wantNull)
	}
}

// TestRunDataMigrationsIsANoOpOnAnEmptyDatabase covers the fresh-install path: there
// is nothing to convert, but the marker must still be written so a later start does
// not rescan every table.
func TestRunDataMigrationsIsANoOpOnAnEmptyDatabase(t *testing.T) {
	newMigrateEnv(t)

	if err := RunDataMigrations(); err != nil {
		t.Fatalf("RunDataMigrations: %v", err)
	}

	var markers int64
	DB.Model(&models.SchemaMigration{}).Where("version = ?", hostCorrelationV1).Count(&markers)
	if markers != 1 {
		t.Errorf("the migration ledger holds %d row(s), want 1 even with nothing to convert", markers)
	}
}

func TestRunDataMigrationsBackfillsSubdomainLastChangedOnce(t *testing.T) {
	id := newMigrateEnv(t)
	seen := time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC)
	if err := DB.Exec(`INSERT INTO subdomains (profile_id, domain, first_seen, last_seen, last_changed)
		VALUES (?, ?, ?, ?, NULL)`, id, "a.example.com", seen, seen).Error; err != nil {
		t.Fatalf("seeding legacy timestamp: %v", err)
	}

	if err := RunDataMigrations(); err != nil {
		t.Fatalf("migrating timestamp: %v", err)
	}

	var row models.Subdomain
	if err := DB.Where("profile_id = ? AND domain = ?", id, "a.example.com").First(&row).Error; err != nil {
		t.Fatalf("reading migrated subdomain: %v", err)
	}
	if !row.LastChanged.Equal(seen) {
		t.Errorf("LastChanged = %s, want legacy LastSeen %s", row.LastChanged, seen)
	}

	// The marker protects the baseline if a later run updates LastSeen normally.
	later := seen.Add(24 * time.Hour)
	if err := DB.Model(&row).Update("last_seen", later).Error; err != nil {
		t.Fatalf("updating last_seen: %v", err)
	}
	if err := RunDataMigrations(); err != nil {
		t.Fatalf("rerunning timestamp migration: %v", err)
	}
	if err := DB.First(&row, row.ID).Error; err != nil {
		t.Fatalf("reloading migrated subdomain: %v", err)
	}
	if !row.LastChanged.Equal(seen) {
		t.Errorf("idempotent migration changed LastChanged to %s, want %s", row.LastChanged, seen)
	}

	var markers int64
	DB.Model(&models.SchemaMigration{}).Where("version = ?", subdomainLastChangedV1).Count(&markers)
	if markers != 1 {
		t.Errorf("migration ledger holds %d row(s) for %s, want 1", markers, subdomainLastChangedV1)
	}
}
