package engine

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	_ "github.com/glebarez/go-sqlite"
)

// Words are deduplicated on disk, requests flow through a fixed worker pool,
// and findings are committed in bounded batches rather than retained per scan.
func (run *runner) RunDirectoryFuzzing(profile *models.Profile, hosts []models.AliveHost, paths []string) (int, error) {
	ctx, cancel := context.WithTimeout(run.ctx, toolTimeout(run.config.Tools.FuzzerTimeoutMinutes))
	defer cancel()
	dir, e := os.MkdirTemp(run.scratch, "icevirtue-fuzzer-")
	if e != nil {
		return 0, e
	}
	defer os.RemoveAll(dir)
	db, e := sql.Open("sqlite", filepath.Join(dir, "words.db"))
	if e != nil {
		return 0, e
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=OFF", "PRAGMA temp_store=FILE", "PRAGMA cache_size=-8192", "PRAGMA page_size=4096", "PRAGMA max_page_count=1048576", "CREATE TABLE words (word TEXT PRIMARY KEY) WITHOUT ROWID"} {
		if _, e = db.ExecContext(ctx, q); e != nil {
			return 0, e
		}
	}
	for _, path := range paths {
		f, e := os.Open(path)
		if e != nil {
			return 0, e
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 4096), 4098)
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			f.Close()
			return 0, e
		}
		stmt, e := tx.PrepareContext(ctx, "INSERT OR IGNORE INTO words(word) VALUES (?)")
		if e != nil {
			tx.Rollback()
			f.Close()
			return 0, e
		}
		n := 0
		for sc.Scan() {
			word := strings.TrimSpace(sc.Text())
			if word == "" || strings.HasPrefix(word, "#") {
				continue
			}
			if _, e = stmt.ExecContext(ctx, word); e != nil {
				break
			}
			n++
			if n%1000 == 0 {
				stmt.Close()
				if e = tx.Commit(); e != nil {
					break
				}
				tx, e = db.BeginTx(ctx, nil)
				if e != nil {
					break
				}
				stmt, e = tx.PrepareContext(ctx, "INSERT OR IGNORE INTO words(word) VALUES (?)")
				if e != nil {
					break
				}
			}
		}
		if stmt != nil {
			stmt.Close()
		}
		scanErr := sc.Err()
		f.Close()
		if e != nil || scanErr != nil {
			if tx != nil {
				tx.Rollback()
			}
			return 0, fmt.Errorf("wordlist preparation failed (4 GiB scratch limit): %w", errors.Join(e, scanErr))
		}
		if e = tx.Commit(); e != nil {
			return 0, e
		}
	}
	observer, closeObserver := newDirectoryObserver()
	defer closeObserver()
	cache := newBaselineCache(directoryWorkers)
	type finding struct {
		row      *models.DirectoryFinding
		redirect *models.RedirectObservation
	}
	var unknown, confirmed, rejected, requestErrors, controls atomic.Int64
	type job struct {
		host models.AliveHost
		word string
	}
	jobs := make(chan job, 100)
	findings := make(chan finding, 100)
	producerErr := make(chan error, 1)
	var wg sync.WaitGroup
	for i := 0; i < directoryWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				base, e := url.Parse(j.host.URL)
				if e != nil || base.Hostname() == "" || (base.Scheme != "http" && base.Scheme != "https") {
					continue
				}
				target := strings.TrimRight(j.host.URL, "/") + "/" + strings.TrimLeft(j.word, "/")
				parsed, e := url.Parse(target)
				if e != nil || parsed.Host != base.Host || parsed.Scheme != base.Scheme || parsed.User != nil {
					continue
				}
				obs, assessment, reason, baselineRequests := classifyDirectory(ctx, observer, cache, parsed, profile.Domain, run.knownHosts)
				controls.Add(int64(baselineRequests))
				if obs.initial == 0 && ctx.Err() == nil {
					requestErrors.Add(1)
				}
				if assessment == "unknown" {
					unknown.Add(1)
					if reason != "matches_missing_paths" && reason != "cross_host" && reason != "cross_scope" {
						requestErrors.Add(1)
					}
				}
				if assessment == "confirmed" {
					confirmed.Add(1)
				}
				if assessment == "" {
					rejected.Add(1)
				}
				var row *models.DirectoryFinding
				if assessment != "" {
					row = &models.DirectoryFinding{ProfileID: profile.ID, SubdomainURL: j.host.URL, DirURL: parsed.String(), StatusCode: obs.initial, Assessment: assessment, AssessmentReason: reason}
				}
				if obs.redirect != nil {
					obs.redirect.ProfileID = profile.ID
					obs.redirect.Host = normalizedHostname(base)
				}
				if row != nil || obs.redirect != nil {
					select {
					case findings <- finding{row, obs.redirect}:
					case <-ctx.Done():
						return
					}
				}

			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, host := range hosts {
			rows, e := db.QueryContext(ctx, "SELECT word FROM words")
			if e != nil {
				producerErr <- e
				return
			}
			for rows.Next() {
				var word string
				if e = rows.Scan(&word); e != nil {
					rows.Close()
					producerErr <- e
					return
				}
				select {
				case jobs <- job{host, word}:
				case <-ctx.Done():
					rows.Close()
					producerErr <- ctx.Err()
					return
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				producerErr <- e
				return
			}
		}
		producerErr <- nil
	}()
	go func() { wg.Wait(); close(findings) }()
	total := 0
	var storageErr error
	batch := make([]models.DirectoryFinding, 0, 100)
	redirects := make([]models.RedirectObservation, 0, 100)
	for finding := range findings {
		if finding.row != nil {
			batch = append(batch, *finding.row)
		}
		if finding.redirect != nil {
			redirects = append(redirects, *finding.redirect)
		}
		if len(batch) >= 100 || len(redirects) >= 100 {
			if storageErr == nil {
				var added int
				added, storageErr = run.storeDirectoryObservations(profile, batch, redirects)
				total += added
				if storageErr != nil {
					cancel()
				}
			}
			batch = batch[:0]
			redirects = redirects[:0]
		}
	}
	if len(batch) > 0 || len(redirects) > 0 {
		if storageErr == nil {
			var added int
			added, storageErr = run.storeDirectoryObservations(profile, batch, redirects)
			total += added
			if storageErr != nil {
				cancel()
			}
		}
	}
	run.fuzzerSummary = fmt.Sprintf("%d baseline requests; %d confirmed observations; %d Unknown observations; %d rejected; %d validation errors", controls.Load(), confirmed.Load(), unknown.Load(), rejected.Load(), requestErrors.Load())
	logf("[Directory validation] %s", run.fuzzerSummary)
	var validationErr error
	if requestErrors.Load() > 0 {
		validationErr = fmt.Errorf("directory validation incomplete: %d observations could not be validated", requestErrors.Load())
	}
	return total, errors.Join(<-producerErr, ctx.Err(), storageErr, validationErr)
}
