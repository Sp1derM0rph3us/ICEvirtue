package api

import (
	"net/http"
	"strconv"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/hostkey"
)

// maxPageSize is the hard ceiling on one response, so a single request cannot be
// made to load an entire profile into memory.
//
// It stays at 1000 even though the dashboard's page-size selector stops at 500:
// lowering it would silently downgrade any operator script that currently asks for
// 1000, which is precisely the bug class fixed in 57239d2. The envelope now reports
// the size that was actually used, so any clamping is visible rather than silent.
const maxPageSize = 1000

// Per-endpoint default page sizes, chosen for how wide each table's rows are.
// Vulnerabilities and secrets carry a title, a severity or a secret value, so fewer
// fit comfortably; subdomains and directories are one line each.
const (
	defaultPageProfiles    = 25
	defaultPageSubdomains  = 100
	defaultPageDirectories = 100
	defaultPageVulns       = 50
	defaultPageSecrets     = 50
	defaultPageHosts       = 100
)

// PageMeta describes the page that was actually served.
//
// Every field is echoed rather than assumed, and that is the point. A caller asking
// for size=5000 gets 1000 back and can see it was clamped; a stale bookmark carrying
// sort=bogus gets the default back and can correct itself. The previous endpoints
// returned a bare JSON array, which is what made truncation undetectable: there was
// nothing in the response to distinguish a partial page from a complete one.
type PageMeta struct {
	Page       int    `json:"page"`
	Size       int    `json:"size"`
	TotalRows  int64  `json:"total_rows"`
	TotalPages int    `json:"total_pages"`
	Sort       string `json:"sort,omitempty"`
	Filter     string `json:"filter,omitempty"`
	Host       string `json:"host,omitempty"`
}

// ListResponse is the shape every list endpoint returns.
type ListResponse[T any] struct {
	// Data is never null. An empty page is [], because a client that cannot tell
	// "no rows" from "no field" is the client this change exists to stop shipping.
	Data []T      `json:"data"`
	Page PageMeta `json:"page"`
}

// listQuery is a validated set of list parameters.
type listQuery struct {
	Page int
	Size int
	Sort string // a key that is known to exist in the endpoint's allowlist
	Host string // normalized; "" means no host scope

	// HostRequested records that the caller asked for a host scope, which has to be
	// distinguishable from asking for none. A host that normalizes to nothing must
	// yield an empty page, never a query that matches the NULL-host rows.
	HostRequested bool

	// legacyOffset preserves an offset that cannot be expressed as a page, so the
	// limit/offset spelling the README documents keeps working exactly.
	legacyOffset    int
	hasLegacyOffset bool
}

// parseListQuery reads the list parameters, validating rather than trusting.
//
// Nothing here rejects a bad value with a 400. An oversized size is clamped, an
// unknown sort falls back to the default, and both are reported in PageMeta — so a
// link someone shared six months ago still renders instead of erroring, while still
// telling the client what it actually got. The one thing that is never silently
// reinterpreted is host: see HostRequested.
func parseListQuery(r *http.Request, defaultSize int, sorts map[string]string, defaultSort string) listQuery {
	q := listQuery{Page: 1, Size: defaultSize, Sort: defaultSort}
	params := r.URL.Query()

	// size, with limit accepted as the older spelling.
	sizeParam := params.Get("size")
	if sizeParam == "" {
		sizeParam = params.Get("limit")
	}
	if v, err := strconv.Atoi(sizeParam); err == nil && v > 0 {
		q.Size = min(v, maxPageSize)
	}

	if v, err := strconv.Atoi(params.Get("page")); err == nil && v > 1 {
		q.Page = v
	}

	// A legacy offset is honoured verbatim only when no page was given, because an
	// offset that is not a multiple of size has no page number to round-trip to.
	if params.Get("page") == "" {
		if v, err := strconv.Atoi(params.Get("offset")); err == nil && v > 0 {
			q.legacyOffset, q.hasLegacyOffset = v, true
		}
	}

	if s := params.Get("sort"); s != "" {
		if _, ok := sorts[s]; ok {
			q.Sort = s
		}
	}

	if h := params.Get("host"); h != "" {
		q.HostRequested = true
		q.Host = hostkey.Normalize(h)
	}

	return q
}

// HostUnresolvable reports that a host scope was asked for but carries no usable
// host. The caller must answer with an empty page: querying for it would either
// match nothing useful or, worse, match the rows whose host is NULL.
func (q listQuery) HostUnresolvable() bool {
	return q.HostRequested && q.Host == ""
}

// resolve turns the requested page into an offset, once the real row count is known.
//
// Clamping against the total is what stops the UI being stuck on "page 40 of 3"
// after a filter narrows the result set: the page is pulled back into range and the
// corrected value is reported, so the client can update its own state.
func (q listQuery) resolve(total int64) (offset int, meta PageMeta) {
	totalPages := 1
	if total > 0 {
		totalPages = int((total + int64(q.Size) - 1) / int64(q.Size))
	}

	page := q.Page
	if q.hasLegacyOffset {
		// Report the page the offset lands in, so a limit/offset caller still gets
		// coherent metadata even when its offset straddles two pages.
		page = q.legacyOffset/q.Size + 1
		offset = q.legacyOffset
	} else {
		if page > totalPages {
			page = totalPages
		}
		if page < 1 {
			page = 1
		}
		offset = (page - 1) * q.Size
	}

	return offset, PageMeta{
		Page:       page,
		Size:       q.Size,
		TotalRows:  total,
		TotalPages: totalPages,
		Sort:       q.Sort,
		Host:       q.Host,
	}
}

// emptyPage is the response for a request that cannot match anything, such as a host
// scope that carries no usable host. It reports the parameters it was given so the
// client can tell "nothing here" apart from "your request was thrown away".
func emptyPage[T any](q listQuery) ListResponse[T] {
	return ListResponse[T]{
		Data: []T{},
		Page: PageMeta{Page: 1, Size: q.Size, TotalRows: 0, TotalPages: 1, Sort: q.Sort, Host: q.Host},
	}
}

// respondList writes a list response, normalising a nil slice to an empty one.
func respondList[T any](w http.ResponseWriter, rows []T, meta PageMeta) {
	if rows == nil {
		rows = []T{}
	}
	respondJSON(w, http.StatusOK, ListResponse[T]{Data: rows, Page: meta})
}
