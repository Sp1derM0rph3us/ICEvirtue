package api

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// The Nodes table. This is the endpoint the whole change is about.
//
// The dashboard used to build this view by downloading every subdomain, host,
// vulnerability, directory and secret in the profile and then, for each rendered row,
// scanning all of those arrays with an unanchored String.includes. For a profile with
// 5000 subdomains and 30000 directories that is roughly 227 million string
// comparisons per render, on the main thread, repeated on every sort, every filter
// click, every tab switch and every eight seconds during a scan.
//
// Here the same page is two indexed queries.

// subdomainRow is what the Nodes table renders.
//
// It is a DTO rather than models.Subdomain because the counts and the status badge are
// products of a query, not columns. Returning them from the server is what removes the
// client-side correlation entirely.
type subdomainRow struct {
	ID     uint    `json:"id"`
	Domain string  `json:"domain"`
	Host   *string `json:"host"`
	// StatusCode is null when no alive host was recorded for this name, which is what
	// the dashboard draws as DEAD.
	StatusCode  *int      `json:"status_code"`
	VulnCount   int       `json:"vuln_count"`
	DirCount    int       `json:"dir_count"`
	SecretCount int       `json:"secret_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// countCap bounds how far a per-row count will walk.
//
// SQLite evaluates a SELECT-list subquery once per *output* row, after LIMIT and OFFSET
// have pruned, so a page of 100 costs 100 index probes per subquery rather than one per
// row in the table — that part is cheap and measured. What is not cheap is that each
// probe is O(matching rows): a single host carrying 40000 directories took 20ms on its
// own, which made whichever page it landed on an order of magnitude slower than its
// neighbours.
//
// The badge needs to tell "none" from "a few" from "a lot", not to render an exact
// 40000, so the count stops at the cap and the client shows "1000+". Measured on that
// same page: 25.2ms to 1.7ms. The exact total is still available and still exact on the
// node's own tab, where the envelope reports it.
const countCap = 1000

func countFor(table, alias string) string {
	return `(SELECT COUNT(*) FROM (SELECT 1 FROM ` + table + ` ` + alias + `
		WHERE ` + alias + `.profile_id = subdomains.profile_id
		  AND ` + alias + `.host = subdomains.host
		  AND ` + alias + `.deleted_at IS NULL
		LIMIT ` + strconv.Itoa(countCap) + `))`
}

// statusExpr is the one definition of "this node's status".
//
// MIN is not an arbitrary pick. httpx can report both an http:// and an https:// URL
// for the same host, and 2xx < 3xx < 4xx < 5xx means MIN prefers the most alive of
// them. More importantly it is deterministic and shared: the badge and all three
// status filters read this same expression, so they cannot disagree. Previously the
// badge used Array.find() over an unordered response while the filters called find()
// again separately, so a node could display 403 and still match the 2xx/3xx pill.
const statusExpr = `(SELECT MIN(a.status_code) FROM alive_hosts a
	WHERE a.profile_id = subdomains.profile_id
	  AND a.host = subdomains.host
	  AND a.deleted_at IS NULL)`

var subdomainSelect = `subdomains.id, subdomains.domain, subdomains.host,
	subdomains.first_seen, subdomains.last_seen,
	` + countFor("vulnerabilities", "v") + ` AS vuln_count,
	` + countFor("directory_findings", "d") + ` AS dir_count,
	` + countFor("secret_findings", "c") + ` AS secret_count,
	` + statusExpr + ` AS status_code`

// ipPredicate matches a name that is a bare IPv4 address. dnsx -resp-only emits A
// record values rather than names, so the subdomains table legitimately contains
// addresses, which is why the dashboard offers an IP filter at all.
//
// GLOB, because SQLite has no REGEXP without registering a function. The second
// clause is what makes it exact enough: the first alone would match any name whose
// labels happen to start with digits.
const ipPredicate = `(subdomains.domain GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
	AND subdomains.domain NOT GLOB '*[^0-9.]*')`

// existsFor builds an EXISTS over one finding table. EXISTS lets the planner stop at
// the first match instead of counting, and inline in the WHERE it can short-circuit
// once enough rows for the page have been found.
func existsFor(table, alias, extra string) string {
	return `EXISTS (SELECT 1 FROM ` + table + ` ` + alias + `
		WHERE ` + alias + `.profile_id = subdomains.profile_id
		  AND ` + alias + `.host = subdomains.host
		  AND ` + alias + `.deleted_at IS NULL` + extra + `)`
}

// subdomainFilters mirrors the dashboard's filter pills in SQL.
//
// They have to run here. Applied on the client they would filter only the rows of the
// page that was already fetched, which looks right and is wrong — the page would be
// "the matching rows out of these 100" rather than "the first 100 matching rows".
var subdomainFilters = map[string]string{
	"ip":        ipPredicate,
	"subdomain": "NOT " + ipPredicate,

	// Anything scored above informational.
	"vuln-critical": existsFor("vulnerabilities", "v",
		` AND lower(v.severity) IN ('critical','high','medium','low')`),

	// Faithful to the pill's original meaning: no vulnerabilities at all, or nothing
	// beyond info. A node with zero findings matches, which is why this is a NOT
	// EXISTS over the non-info ones rather than an EXISTS over the info ones.
	"vuln-info": "NOT " + existsFor("vulnerabilities", "v", ` AND lower(v.severity) <> 'info'`),

	"secrets": existsFor("secret_findings", "c", ""),

	"status-2xx-3xx": statusExpr + " BETWEEN 200 AND 399",
	"status-403":     statusExpr + " = 403",
	// IS NOT NULL reproduces the original behaviour, which tested a host was found
	// before looking at its code, so a DEAD node does not match "Others".
	"status-other": statusExpr + ` IS NOT NULL AND (` + statusExpr + ` < 200
		OR (` + statusExpr + ` >= 400 AND ` + statusExpr + ` <> 403))`,

	// Seen again on a later scan than the one that discovered it. julianday parses the
	// stored TEXT timestamp including its UTC offset; the threshold is one second
	// expressed in days, matching the original 1000ms comparison.
	"updated": `julianday(subdomains.last_seen) - julianday(subdomains.first_seen) > 1.0/86400.0`,
}

// subdomainSorts maps the dashboard's sort options to a total order.
//
// findings-desc and findings-asc are absent here because they cannot be expressed as
// a plain ORDER BY over this query: see listSubdomainsByVolume.
var subdomainSorts = map[string]string{
	"name-asc":      "subdomains.domain ASC, subdomains.id ASC",
	"name-desc":     "subdomains.domain DESC, subdomains.id DESC",
	"first-asc":     "subdomains.id ASC",
	"first-desc":    "subdomains.id DESC",
	"update-asc":    "subdomains.last_seen ASC, subdomains.id ASC",
	"update-desc":   "subdomains.last_seen DESC, subdomains.id DESC",
	"findings-desc": "",
	"findings-asc":  "",
}

func sortsByVolume(sort string) bool {
	return sort == "findings-desc" || sort == "findings-asc"
}

func getProfileSubdomains(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}

	q := parseListQuery(r, defaultPageSubdomains, subdomainSorts, "name-asc")
	filter := r.URL.Query().Get("filter")
	predicate, filterKnown := subdomainFilters[filter]
	if !filterKnown {
		// An unknown filter is dropped rather than rejected, and the empty value is
		// echoed back, so a stale bookmark degrades to "unfiltered" visibly instead of
		// erroring or silently filtering by something else.
		filter, predicate = "", ""
	}

	scope := func(db *gorm.DB) *gorm.DB {
		db = db.Where("subdomains.profile_id = ?", id)
		if predicate != "" {
			db = db.Where(predicate)
		}
		return db
	}

	var rows []subdomainRow
	var meta PageMeta

	err := database.DB.Transaction(func(tx *gorm.DB) error {
		// One snapshot for the count and the page, so the total and the rows agree.
		var total int64
		if err := scope(tx.Model(&models.Subdomain{})).Count(&total).Error; err != nil {
			return err
		}

		offset, m := q.resolve(total)
		meta = m

		if sortsByVolume(q.Sort) {
			return listSubdomainsByVolume(tx, scope, q, offset, &rows)
		}
		return scope(tx.Model(&models.Subdomain{})).
			Select(subdomainSelect).
			Order(subdomainSorts[q.Sort]).
			Limit(q.Size).Offset(offset).
			Scan(&rows).Error
	})
	if err != nil {
		log.Printf("[-] Listing subdomains for %s: %v", id, err)
		http.Error(w, "failed to list subdomains", http.StatusInternalServerError)
		return
	}

	meta.Filter = filter
	respondList(w, rows, meta)
}

// listSubdomainsByVolume sorts by total findings, which is the one sort that cannot be
// index-ordered: the value being sorted on is computed per row.
//
// The counts are wrapped in a subselect and the ORDER BY reads the aliases from
// outside it. SQLite does accept the aliases in the outer expression of a single-level
// query, but doing it that way re-evaluates all three subqueries for every comparison
// — measured at five times slower on a realistic profile. Wrapping computes them once
// per candidate row.
//
// The counts it sorts on are capped at countCap, so hosts above the cap rank as equal.
// That is the intended reading -- they are all "a lot" -- and it bounds what would
// otherwise be the most expensive query in the schema.
//
// This costs a full pass over the filtered set rather than a page, so it is the one
// option here whose price does not fall with pagination. At a few milliseconds for
// 5000 subdomains that is worth paying, and page 50 costs the same as page 1 because
// the sort is materialised either way. It is deliberately not capped or hidden: doing
// that would be the same class of quiet wrongness as the truncation this replaces.
func listSubdomainsByVolume(tx *gorm.DB, scope func(*gorm.DB) *gorm.DB, q listQuery, offset int, rows *[]subdomainRow) error {
	inner := scope(tx.Model(&models.Subdomain{})).Select(subdomainSelect)

	direction := "DESC"
	if q.Sort == "findings-asc" {
		direction = "ASC"
	}

	return tx.Table("(?) AS ranked", inner).
		Order("(vuln_count + dir_count + secret_count) " + direction + ", domain ASC, id ASC").
		Limit(q.Size).Offset(offset).
		Scan(rows).Error
}
