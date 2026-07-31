package database

import (
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/hostkey"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// hostCorrelationV1 backfills the host column that findings are correlated to
// subdomains by. Before it existed the dashboard matched a subdomain name against a
// finding's whole URL with an unanchored substring search, in the browser, over the
// entire dataset.
const hostCorrelationV1 = "2026_07_host_correlation_v1"

// backfillBatch is how many rows one transaction converts.
//
// It is also the crash-loss unit, which is why it is not much larger: a batch is
// cheap to redo. 500 rowid updates plus their partial-index inserts commit in single
// digit milliseconds under WAL with synchronous=NORMAL.
const backfillBatch = 500

// hostSources names the column each table's correlation key is derived from. The
// same value is passed to hostkey.Normalize on the read side, which is what makes
// the join an equality rather than a guess.
var hostSources = []struct{ table, source string }{
	{"subdomains", "domain"},
	{"alive_hosts", "url"},
	{"vulnerabilities", "url"},
	{"secret_findings", "source_url"},
	{"directory_findings", "subdomain_url"},
}

// RunDataMigrations applies the one-time data migrations an existing database needs.
//
// It is separate from InitDatabase on purpose: cmd/admin also opens the database,
// and creating a user has no business running a data migration. Call it from main
// after InitDatabase and before the scheduler and the HTTP server start — at that
// point nothing else can hold the single connection the pool is limited to, so the
// only cost is startup latency rather than contention with live requests.
//
// It is synchronous for a reason. Backfilling in the background would leave a window
// in which every per-node finding count reads zero, which is a wrong answer served
// confidently — the exact failure this whole change exists to remove.
func RunDataMigrations() error {
	applied, err := migrationApplied(hostCorrelationV1)
	if err != nil {
		return err
	}
	if applied {
		return nil
	}

	started := time.Now()
	var converted, unresolved int

	for _, src := range hostSources {
		n, bad, err := backfillHost(src.table, src.source)
		if err != nil {
			// Deliberately fatal to the caller. A half-backfilled database would
			// under-report every finding count, and the marker row is not written, so
			// the next start retries from where this one stopped.
			return fmt.Errorf("backfilling %s.host from %s: %w", src.table, src.source, err)
		}
		converted += n
		unresolved += bad
	}

	if converted > 0 || unresolved > 0 {
		log.Printf("[+] Correlated %d existing finding(s) to their host in %s",
			converted, time.Since(started).Round(time.Millisecond))
		if unresolved > 0 {
			// One aggregate line, never one per row: on a large database that would be
			// tens of thousands of log lines for a condition that is usually benign
			// (mantra reports its findings against a placeholder rather than a URL).
			log.Printf("[*] %d of those carried no usable host and are attributed to no node", unresolved)
		}
	}

	return markMigrationApplied(hostCorrelationV1)
}

func migrationApplied(version string) (bool, error) {
	var n int64
	if err := DB.Model(&models.SchemaMigration{}).Where("version = ?", version).Count(&n).Error; err != nil {
		return false, fmt.Errorf("reading the migration ledger: %w", err)
	}
	return n > 0, nil
}

func markMigrationApplied(version string) error {
	// DoNothing on conflict because an operator can legitimately start the service
	// and ICEvirtue-admin against the same not-yet-migrated database at once. The
	// updates themselves are idempotent, so the worst case is duplicated work; only
	// the marker insert would otherwise fail on its primary key.
	err := DB.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&models.SchemaMigration{Version: version}).Error
	if err != nil {
		return fmt.Errorf("recording migration %s: %w", version, err)
	}
	return nil
}

// backfillHost walks one table by keyset and fills in the host column.
//
// The normalization deliberately happens in Go rather than in SQL. SQLite has no URL
// parser, so an SQL version would be a second implementation of the join key built
// out of instr/substr — and on the day the two drift, findings silently detach from
// the nodes they belong to. One implementation, used by the write hooks, the read
// side and this backfill.
func backfillHost(table, source string) (converted, unresolved int, err error) {
	type row struct {
		ID     uint64
		Source string
	}

	var cursor uint64
	for {
		var rows []row
		// Table() with a raw name carries no model, so GORM adds no soft-delete
		// clause: soft-deleted rows are backfilled too. That is intended — they are
		// still in the file, and an operator who restores one should not get a row
		// that silently correlates to nothing.
		//
		// The keyset walk on id is what makes this resumable after a crash and what
		// guarantees termination: rows that legitimately end up NULL are behind the
		// cursor, so the "host IS NULL" predicate cannot make the loop revisit them.
		err = DB.Table(table).
			Select("id, "+source+" AS source").
			Where("id > ? AND host IS NULL", cursor).
			Order("id").
			Limit(backfillBatch).
			Scan(&rows).Error
		if err != nil {
			return converted, unresolved, err
		}
		if len(rows) == 0 {
			return converted, unresolved, nil
		}

		// Parse outside the transaction so the write lock is held only for the writes.
		hosts := make([]interface{}, len(rows))
		for i, r := range rows {
			if host := hostkey.Normalize(r.Source); host != "" {
				hosts[i] = host
			} else {
				// Left as NULL, which is the whole point: nothing can ever join to it.
				unresolved++
			}
		}

		err = DB.Transaction(func(tx *gorm.DB) error {
			// Only tx in here. Reaching for the package-level DB inside a transaction
			// would wait for a connection from a pool of exactly one that this
			// transaction is already holding, and database/sql waits without a
			// timeout — a permanent hang rather than a slow query.
			for i, r := range rows {
				if e := tx.Exec("UPDATE "+table+" SET host = ? WHERE id = ?", hosts[i], r.ID).Error; e != nil {
					return e
				}
			}
			return nil
		})
		if err != nil {
			return converted, unresolved, err
		}

		converted += len(rows)
		cursor = rows[len(rows)-1].ID
	}
}
