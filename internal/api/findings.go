package api

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// The finding list endpoints. Each one serves a single page, sorted and filtered by
// the database, with a total count so the client can render pagination.
//
// They used to return a bare, unordered slice, which was wrong in two ways that
// compounded: without an ORDER BY, two LIMIT/OFFSET requests against the same table
// could legally overlap or skip rows, and without a total the client could not tell a
// partial answer from a complete one. The dashboard worked around the second by
// downloading everything and correlating in JavaScript, which is the performance
// problem this replaces.

// profileID reads and validates the profile id from the URL.
//
// This was copy-pasted into eight handlers. It is one function now, so the id can
// never be parsed one way in one endpoint and another way somewhere else.
func profileID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	idParam := chi.URLParam(r, "id")
	if idParam == "" {
		http.Error(w, "missing profile id", http.StatusBadRequest)
		return uuid.Nil, false
	}

	id, err := uuid.Parse(idParam)
	if err != nil {
		http.Error(w, "invalid UUID format", http.StatusBadRequest)
		return uuid.Nil, false
	}
	return id, true
}

// listPage runs the count and the page inside one read transaction and writes the
// response.
//
// The transaction is not decoration. Counting and then selecting in two separate
// statements lets a row land in between, which produces a total the rows do not add
// up to and, on the last page, a "page 4 of 3". One snapshot makes the two agree.
//
// scope must apply every WHERE the caller wants counted; order is the full ORDER BY.
// The generic parameter is the row type, which may be a model or a DTO.
func listPage[T any](
	w http.ResponseWriter,
	q listQuery,
	model interface{},
	selectClause string,
	scope func(*gorm.DB) *gorm.DB,
	order string,
) {
	var rows []T
	var meta PageMeta

	err := database.DB.Transaction(func(tx *gorm.DB) error {
		// Only tx inside here. Reaching for database.DB would wait for a connection
		// from a pool of exactly one that this transaction already holds, and
		// database/sql waits with no timeout: a permanent hang, not a slow query.
		var total int64
		if err := scope(tx.Model(model)).Count(&total).Error; err != nil {
			return err
		}

		offset, m := q.resolve(total)
		meta = m

		query := scope(tx.Model(model))
		if selectClause != "" {
			query = query.Select(selectClause)
		}
		return query.Order(order).Limit(q.Size).Offset(offset).Scan(&rows).Error
	})
	if err != nil {
		log.Printf("[-] Listing findings: %v", err)
		http.Error(w, "failed to list findings", http.StatusInternalServerError)
		return
	}

	respondList(w, rows, meta)
}

// hostScope narrows a finding query to one host, for the node detail view.
//
// The host is compared for equality against the normalized key, which is what makes
// this an index seek. The caller must have already rejected a host that normalizes to
// nothing — see listQuery.HostUnresolvable — because reaching here with an empty host
// would silently match the rows whose host is NULL.
func hostScope(q listQuery, table string) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if q.Host != "" {
			return db.Where(table+".host = ?", q.Host)
		}
		return db
	}
}

// profileScope is the base restriction every finding query carries.
func profileScope(id uuid.UUID, table string, extra ...func(*gorm.DB) *gorm.DB) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		db = db.Where(table+".profile_id = ?", id)
		for _, fn := range extra {
			db = fn(db)
		}
		return db
	}
}

// severityRank orders by how much a finding matters rather than by its name.
// Alphabetical severity sorts critical, high, info, low, medium — which puts the
// least interesting class third.
const severityRank = `CASE lower(vulnerabilities.severity)
	WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
	WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END`

// Every ORDER BY ends with a unique column. Without that tiebreaker the order of rows
// sharing a sort key is unspecified, and LIMIT/OFFSET paging over an unstable order is
// free to show the same row twice and never show another.
var (
	vulnSorts = map[string]string{
		"severity-desc": severityRank + " ASC, vulnerabilities.url ASC, vulnerabilities.id ASC",
		"severity-asc":  severityRank + " DESC, vulnerabilities.url ASC, vulnerabilities.id ASC",
		"url-asc":       "vulnerabilities.url ASC, vulnerabilities.id ASC",
		"name-asc":      "vulnerabilities.name ASC, vulnerabilities.id ASC",
		"first-desc":    "vulnerabilities.id DESC",
		"first-asc":     "vulnerabilities.id ASC",
	}
	dirSorts = map[string]string{
		"url-asc":     "directory_findings.dir_url ASC, directory_findings.id ASC",
		"url-desc":    "directory_findings.dir_url DESC, directory_findings.id DESC",
		"status-asc":  "directory_findings.status_code ASC, directory_findings.dir_url ASC, directory_findings.id ASC",
		"status-desc": "directory_findings.status_code DESC, directory_findings.dir_url ASC, directory_findings.id ASC",
		"first-desc":  "directory_findings.id DESC",
		"first-asc":   "directory_findings.id ASC",
	}
	secretSorts = map[string]string{
		"type-asc":   "secret_findings.secret_type ASC, secret_findings.id ASC",
		"type-desc":  "secret_findings.secret_type DESC, secret_findings.id DESC",
		"first-desc": "secret_findings.id DESC",
		"first-asc":  "secret_findings.id ASC",
	}
	hostSorts = map[string]string{
		"url-asc":     "alive_hosts.url ASC, alive_hosts.id ASC",
		"url-desc":    "alive_hosts.url DESC, alive_hosts.id DESC",
		"status-asc":  "alive_hosts.status_code ASC, alive_hosts.url ASC, alive_hosts.id ASC",
		"status-desc": "alive_hosts.status_code DESC, alive_hosts.url ASC, alive_hosts.id ASC",
	}
)

// first-asc and first-desc order by id rather than by first_seen. id is
// AUTOINCREMENT, so it is exactly insertion order, and it avoids two problems with
// the timestamp: it is stored as TEXT carrying a local UTC offset, so ordering by it
// inverts across a daylight-saving fall-back, and it would need an index of its own.

func getProfileVulnerabilities(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}

	q := parseListQuery(r, defaultPageVulns, vulnSorts, "severity-desc")
	if q.HostUnresolvable() {
		respondJSON(w, http.StatusOK, emptyPage[models.Vulnerability](q))
		return
	}

	listPage[models.Vulnerability](w, q, &models.Vulnerability{}, "",
		profileScope(id, "vulnerabilities", hostScope(q, "vulnerabilities")), vulnSorts[q.Sort])
}

func getProfileDirectories(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}

	q := parseListQuery(r, defaultPageDirectories, dirSorts, "url-asc")
	if q.HostUnresolvable() {
		respondJSON(w, http.StatusOK, emptyPage[models.DirectoryFinding](q))
		return
	}

	listPage[models.DirectoryFinding](w, q, &models.DirectoryFinding{}, "",
		profileScope(id, "directory_findings", hostScope(q, "directory_findings")), dirSorts[q.Sort])
}

func getProfileSecrets(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}

	q := parseListQuery(r, defaultPageSecrets, secretSorts, "type-asc")
	if q.HostUnresolvable() {
		respondJSON(w, http.StatusOK, emptyPage[models.SecretFinding](q))
		return
	}

	listPage[models.SecretFinding](w, q, &models.SecretFinding{}, "",
		profileScope(id, "secret_findings", hostScope(q, "secret_findings")), secretSorts[q.Sort])
}

func getProfileHosts(w http.ResponseWriter, r *http.Request) {
	id, ok := profileID(w, r)
	if !ok {
		return
	}

	q := parseListQuery(r, defaultPageHosts, hostSorts, "url-asc")
	if q.HostUnresolvable() {
		respondJSON(w, http.StatusOK, emptyPage[models.AliveHost](q))
		return
	}

	listPage[models.AliveHost](w, q, &models.AliveHost{}, "",
		profileScope(id, "alive_hosts", hostScope(q, "alive_hosts")), hostSorts[q.Sort])
}
