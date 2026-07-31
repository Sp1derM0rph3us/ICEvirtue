package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// decodePage decodes a list response. The envelope is the point of these tests: the
// endpoints used to return a bare array, which is what made a truncated page
// indistinguishable from a complete one.
func decodePage[T any](t *testing.T, rec *httptest.ResponseRecorder, what string) ListResponse[T] {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200: %s", what, rec.Code, rec.Body.String())
	}
	var page ListResponse[T]
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decoding %s: %v\nbody: %s", what, err, rec.Body.String())
	}
	return page
}

func getSubdomainPage(t *testing.T, id fmt.Stringer, query string) ListResponse[subdomainRow] {
	t.Helper()

	rec := route(t, http.MethodGet, "/api/profiles/{id}/subdomains",
		"/api/profiles/"+id.String()+"/subdomains"+query, getProfileSubdomains)
	return decodePage[subdomainRow](t, rec, "subdomains"+query)
}

func TestParseListQueryClampsAndEchoes(t *testing.T) {
	sorts := map[string]string{"name-asc": "a", "name-desc": "b"}

	cases := []struct {
		query    string
		wantSize int
		wantPage int
		wantSort string
		wantHost string
		unusable bool
	}{
		{"", defaultPageSubdomains, 1, "name-asc", "", false},
		// Clamped, not rejected. Rejecting used to fall back to the default, so a
		// caller asking for 5000 silently received 250.
		{"?size=5000", maxPageSize, 1, "name-asc", "", false},
		{"?size=250", 250, 1, "name-asc", "", false},
		{"?size=0", defaultPageSubdomains, 1, "name-asc", "", false},
		{"?size=-7", defaultPageSubdomains, 1, "name-asc", "", false},
		{"?size=abc", defaultPageSubdomains, 1, "name-asc", "", false},
		// limit is the older spelling and keeps working.
		{"?limit=500", 500, 1, "name-asc", "", false},
		{"?limit=5000", maxPageSize, 1, "name-asc", "", false},
		{"?page=4", defaultPageSubdomains, 4, "name-asc", "", false},
		{"?page=0", defaultPageSubdomains, 1, "name-asc", "", false},
		// An unknown sort degrades to the default rather than erroring, so a stale
		// bookmark still renders.
		{"?sort=bogus", defaultPageSubdomains, 1, "name-asc", "", false},
		{"?sort=name-desc", defaultPageSubdomains, 1, "name-desc", "", false},
		// host is normalized with the same function the write path uses.
		{"?host=A.Example.COM.", defaultPageSubdomains, 1, "name-asc", "a.example.com", false},
		{"?host=https://a.example.com/x", defaultPageSubdomains, 1, "name-asc", "a.example.com", false},
		// A host that carries nothing usable must be distinguishable from no host at
		// all, or the query would match the NULL-host rows.
		{"?host=mantra-discovery", defaultPageSubdomains, 1, "name-asc", "", true},
	}

	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/api/profiles/x/subdomains"+c.query, nil)
		q := parseListQuery(req, defaultPageSubdomains, sorts, "name-asc")

		if q.Size != c.wantSize || q.Page != c.wantPage || q.Sort != c.wantSort || q.Host != c.wantHost {
			t.Errorf("parseListQuery(%q) = {size:%d page:%d sort:%q host:%q}, want {size:%d page:%d sort:%q host:%q}",
				c.query, q.Size, q.Page, q.Sort, q.Host, c.wantSize, c.wantPage, c.wantSort, c.wantHost)
		}
		if q.HostUnresolvable() != c.unusable {
			t.Errorf("parseListQuery(%q).HostUnresolvable() = %v, want %v", c.query, q.HostUnresolvable(), c.unusable)
		}
	}
}

// TestResolveClampsThePageAgainstTheTotal is what stops the UI being stuck on
// "page 40 of 3" after a filter narrows the result set.
func TestResolveClampsThePageAgainstTheTotal(t *testing.T) {
	q := listQuery{Page: 40, Size: 100, Sort: "name-asc"}

	offset, meta := q.resolve(250)
	if meta.TotalPages != 3 {
		t.Errorf("TotalPages = %d, want 3", meta.TotalPages)
	}
	if meta.Page != 3 {
		t.Errorf("Page = %d, want it clamped to 3", meta.Page)
	}
	if offset != 200 {
		t.Errorf("offset = %d, want 200", offset)
	}

	// An empty result set is page 1 of 1, never page 0 of 0.
	_, empty := listQuery{Page: 1, Size: 100}.resolve(0)
	if empty.Page != 1 || empty.TotalPages != 1 {
		t.Errorf("empty set reported page %d of %d, want 1 of 1", empty.Page, empty.TotalPages)
	}
}

// TestSubdomainPagesPartitionEveryRow is the guard for the missing ORDER BY. Without a
// total order, two LIMIT/OFFSET requests against an unchanged table are free to return
// the same row twice and never return another — which is silent, and which the old
// endpoints did.
func TestSubdomainPagesPartitionEveryRow(t *testing.T) {
	profile := newAPIEnv(t)

	const total = 250
	for i := range total {
		// Deliberately not in name order, so a bug that relies on insertion order
		// showing up as name order cannot hide.
		sub := models.Subdomain{
			ProfileID: profile.ID,
			Domain:    fmt.Sprintf("host-%04d.example.com", (i*97)%total),
		}
		if err := database.DB.Create(&sub).Error; err != nil {
			t.Fatalf("seeding subdomain %d: %v", i, err)
		}
	}

	for _, sort := range []string{"name-asc", "name-desc", "first-asc", "first-desc", "update-desc", "findings-desc"} {
		seen := make(map[uint]bool, total)
		const size = 40

		for page := 1; ; page++ {
			got := getSubdomainPage(t, profile.ID, fmt.Sprintf("?sort=%s&size=%d&page=%d", sort, size, page))

			if got.Page.TotalRows != total {
				t.Fatalf("sort=%s page=%d: TotalRows = %d, want %d", sort, page, got.Page.TotalRows, total)
			}
			if got.Page.Sort != sort {
				t.Errorf("sort=%s: envelope echoed %q", sort, got.Page.Sort)
			}
			for _, row := range got.Data {
				if seen[row.ID] {
					t.Fatalf("sort=%s: row %d appeared on more than one page", sort, row.ID)
				}
				seen[row.ID] = true
			}
			if page >= got.Page.TotalPages {
				break
			}
		}

		if len(seen) != total {
			t.Errorf("sort=%s: paging covered %d distinct rows, want %d", sort, len(seen), total)
		}
	}
}

// TestSubdomainPageSizeIsHonouredAndReported covers the envelope's job of telling the
// client what it actually got.
func TestSubdomainPageSizeIsHonouredAndReported(t *testing.T) {
	profile := newAPIEnv(t)

	for i := range 120 {
		if err := database.DB.Create(&models.Subdomain{
			ProfileID: profile.ID, Domain: fmt.Sprintf("host-%04d.example.com", i),
		}).Error; err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}

	got := getSubdomainPage(t, profile.ID, "")
	if len(got.Data) != 100 || got.Page.Size != 100 {
		t.Errorf("default page returned %d rows with size %d, want 100 and 100", len(got.Data), got.Page.Size)
	}
	if got.Page.TotalRows != 120 || got.Page.TotalPages != 2 {
		t.Errorf("envelope reported %d rows over %d pages, want 120 over 2", got.Page.TotalRows, got.Page.TotalPages)
	}

	last := getSubdomainPage(t, profile.ID, "?page=2")
	if len(last.Data) != 20 {
		t.Errorf("last page returned %d rows, want 20", len(last.Data))
	}

	// An oversized size comes back clamped, and the client can see it.
	clamped := getSubdomainPage(t, profile.ID, "?size=5000")
	if clamped.Page.Size != maxPageSize {
		t.Errorf("size=5000 reported Size %d, want the clamped %d", clamped.Page.Size, maxPageSize)
	}
}

// TestEmptyPageIsAnArrayNotNull matters because a client that cannot tell "no rows"
// from "no field" is the client this whole change exists to stop shipping.
func TestEmptyPageIsAnArrayNotNull(t *testing.T) {
	profile := newAPIEnv(t)

	rec := route(t, http.MethodGet, "/api/profiles/{id}/subdomains",
		"/api/profiles/"+profile.ID.String()+"/subdomains", getProfileSubdomains)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if string(raw["data"]) != "[]" {
		t.Errorf("data = %s, want []", raw["data"])
	}
}
