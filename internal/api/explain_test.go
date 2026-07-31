package api

import (
	"fmt"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// These tests assert that the hot queries use the indexes they were designed around.
//
// They exist because the failure mode is silent. If SQLite cannot prove that GORM's
// table-qualified `deleted_at IS NULL` implies a partial index's unqualified
// predicate, or if a future edit reorders a WHERE, the query degrades to a full scan
// and nothing breaks — it just gets slow again, at a scale no test database reaches.
// Asserting the query plan is what keeps the cost model in the comments true.

// explain returns the query plan for whatever GORM would send for the given builder.
func explain(t *testing.T, build func(*gorm.DB) *gorm.DB) []string {
	t.Helper()

	stmt := build(database.DB.Session(&gorm.Session{DryRun: true})).Statement
	sql := database.DB.Dialector.Explain(stmt.SQL.String(), stmt.Vars...)

	var plan []struct {
		Detail string
	}
	if err := database.DB.Raw("EXPLAIN QUERY PLAN " + sql).Scan(&plan).Error; err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN failed for:\n  %s\n  %v", sql, err)
	}

	out := make([]string, 0, len(plan))
	for _, p := range plan {
		out = append(out, p.Detail)
	}
	if len(out) == 0 {
		t.Fatalf("empty query plan for:\n  %s", sql)
	}
	return out
}

func assertUsesIndex(t *testing.T, what, index string, plan []string) {
	t.Helper()

	joined := strings.Join(plan, " | ")
	if !strings.Contains(joined, index) {
		t.Errorf("%s does not use %s:\n  %s", what, index, joined)
	}
	if strings.Contains(joined, "SCAN "+strings.SplitN(index, "_", 2)[0]) {
		t.Errorf("%s degraded to a table scan:\n  %s", what, joined)
	}
}

func TestCorrelationQueriesUseTheirPartialIndexes(t *testing.T) {
	profile := newAPIEnv(t)
	id := profile.ID
	host := "a.example.com"

	// A few rows so the planner has statistics to work with rather than an empty table.
	for i := range 50 {
		database.DB.Create(&models.Subdomain{ProfileID: id, Domain: fmt.Sprintf("h%02d.example.com", i)})
		database.DB.Create(&models.AliveHost{ProfileID: id, URL: fmt.Sprintf("https://h%02d.example.com", i), StatusCode: 200})
		database.DB.Create(&models.Vulnerability{ProfileID: id, TemplateID: fmt.Sprintf("t%d", i),
			URL: fmt.Sprintf("https://h%02d.example.com/x", i), Severity: "info"})
		database.DB.Create(&models.DirectoryFinding{ProfileID: id,
			SubdomainURL: fmt.Sprintf("https://h%02d.example.com", i),
			DirURL:       fmt.Sprintf("https://h%02d.example.com/d", i), StatusCode: 200})
		database.DB.Create(&models.SecretFinding{ProfileID: id,
			SourceURL: fmt.Sprintf("https://h%02d.example.com/a.js", i), SecretType: "aws",
			SecretValue: fmt.Sprintf("AKIA%d", i)})
	}
	database.DB.Exec("ANALYZE")

	cases := []struct {
		what, index string
		model       interface{}
		table       string
	}{
		{"per-host vulnerability count", "idx_vuln_host", &models.Vulnerability{}, "vulnerabilities"},
		{"per-host directory count", "idx_dir_host", &models.DirectoryFinding{}, "directory_findings"},
		{"per-host secret count", "idx_secret_host", &models.SecretFinding{}, "secret_findings"},
		{"per-host status", "idx_host_status", &models.AliveHost{}, "alive_hosts"},
	}

	for _, c := range cases {
		plan := explain(t, func(db *gorm.DB) *gorm.DB {
			return db.Model(c.model).
				Where(c.table+".profile_id = ? AND "+c.table+".host = ?", id, host).
				Find(c.model)
		})
		assertUsesIndex(t, c.what, c.index, plan)
	}
}

// TestSubdomainPageIsIndexOrdered asserts the default page needs no sort step. A
// "USE TEMP B-TREE FOR ORDER BY" here would mean every page materialises and sorts the
// whole profile before slicing, which is exactly the cost pagination is meant to avoid.
func TestSubdomainPageIsIndexOrdered(t *testing.T) {
	profile := newAPIEnv(t)
	for i := range 200 {
		database.DB.Create(&models.Subdomain{ProfileID: profile.ID, Domain: fmt.Sprintf("h%03d.example.com", i)})
	}
	database.DB.Exec("ANALYZE")

	// Select and Scan, exactly as the handler does. Find would make GORM infer the
	// column list from the DTO's fields, which asks for columns that do not exist —
	// the counts are subqueries, not columns.
	plan := explain(t, func(db *gorm.DB) *gorm.DB {
		var rows []subdomainRow
		return db.Model(&models.Subdomain{}).
			Where("subdomains.profile_id = ?", profile.ID).
			Select(subdomainSelect).
			Order(subdomainSorts["name-asc"]).
			Limit(100).Offset(100).
			Scan(&rows)
	})

	joined := strings.Join(plan, " | ")
	// A full "USE TEMP B-TREE FOR ORDER BY" would mean the whole profile is
	// materialised and sorted before the page is sliced off, which is the cost
	// pagination exists to avoid. "FOR RIGHT PART OF ORDER BY" is a different and
	// acceptable thing: the index supplies the leading key and only the trailing
	// tiebreaker is sorted, within groups that are singletons here.
	if strings.Contains(joined, "USE TEMP B-TREE FOR ORDER BY") {
		t.Errorf("the default subdomain page sorts the whole profile instead of walking an index:\n  %s", joined)
	}
	if !strings.Contains(joined, "idx_") {
		t.Errorf("the default subdomain page uses no index at all:\n  %s", joined)
	}
	t.Logf("default page plan: %s", joined)
}

// TestNodeDirectoryListingIsIndexOrdered covers the worst table in the schema: the one
// that can hold tens of thousands of rows for a single host, which is the view the
// original slowness complaint was about.
func TestNodeDirectoryListingIsIndexOrdered(t *testing.T) {
	profile := newAPIEnv(t)
	host := "hot.example.com"
	for i := range 300 {
		database.DB.Create(&models.DirectoryFinding{
			ProfileID: profile.ID, SubdomainURL: "https://" + host,
			DirURL: fmt.Sprintf("https://%s/d%04d", host, i), StatusCode: 200,
		})
	}
	database.DB.Exec("ANALYZE")

	plan := explain(t, func(db *gorm.DB) *gorm.DB {
		var rows []models.DirectoryFinding
		return db.Model(&models.DirectoryFinding{}).
			Where("directory_findings.profile_id = ? AND directory_findings.host = ?", profile.ID, host).
			Order(dirSorts["url-asc"]).
			Limit(100).Offset(200).
			Find(&rows)
	})

	joined := strings.Join(plan, " | ")
	assertUsesIndex(t, "the node directory listing", "idx_dir_host", plan)
	if strings.Contains(joined, "USE TEMP B-TREE FOR ORDER BY") {
		t.Errorf("the node directory listing sorts every row instead of walking idx_dir_host:\n  %s", joined)
	}
	t.Logf("node directory plan: %s", joined)
}

// TestPartialIndexSurvivesGormsQualifiedSoftDeleteClause is the specific risk the plan
// flagged: the indexes are partial on an unqualified `deleted_at IS NULL`, while GORM
// emits `"table"."deleted_at" IS NULL`. If SQLite could not match the two, every one of
// these indexes would be quietly unusable.
func TestPartialIndexSurvivesGormsQualifiedSoftDeleteClause(t *testing.T) {
	profile := newAPIEnv(t)
	for i := range 50 {
		database.DB.Create(&models.Vulnerability{
			ProfileID: profile.ID, TemplateID: fmt.Sprintf("t%d", i),
			URL: fmt.Sprintf("https://h%02d.example.com/x", i), Severity: "info",
		})
	}
	database.DB.Exec("ANALYZE")

	stmt := database.DB.Session(&gorm.Session{DryRun: true}).
		Model(&models.Vulnerability{}).
		Where("vulnerabilities.profile_id = ? AND vulnerabilities.host = ?", profile.ID, "h01.example.com").
		Find(&[]models.Vulnerability{}).Statement
	sql := database.DB.Dialector.Explain(stmt.SQL.String(), stmt.Vars...)

	if !strings.Contains(sql, "`vulnerabilities`.`deleted_at` IS NULL") {
		t.Fatalf("GORM no longer emits a qualified soft-delete clause; this test is checking the wrong thing:\n  %s", sql)
	}

	var plan []struct{ Detail string }
	database.DB.Raw("EXPLAIN QUERY PLAN " + sql).Scan(&plan)
	joined := ""
	for _, p := range plan {
		joined += p.Detail + " | "
	}
	if !strings.Contains(joined, "idx_vuln_host") {
		t.Errorf("the partial index is unusable with GORM's qualified clause:\n  %s\n  %s", sql, joined)
	}
}
