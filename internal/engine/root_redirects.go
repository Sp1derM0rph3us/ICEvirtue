package engine

import (
	"context"
	"fmt"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"net/url"
	"sync"
	"time"
)

// HTTP validation already recorded the root status. This independent observation
// supplies only redirect evidence and never mutates AliveHost.StatusCode.
func (run *runner) inspectRootRedirects(p *models.Profile, hosts []models.AliveHost) (int, error) {
	ctx, cancel := context.WithTimeout(run.ctx, toolTimeout(run.config.Tools.HTTPXTimeoutMinutes))
	defer cancel()
	observer, closeObserver := newDirectoryObserver()
	defer closeObserver()
	work := make(chan models.AliveHost)
	type result struct {
		redirect *models.RedirectObservation
		failed   bool
	}
	results := make(chan result, directoryWorkers)
	var wg sync.WaitGroup
	for i := 0; i < directoryWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range work {
				target, e := url.Parse(h.URL)
				if e != nil || target.Hostname() == "" {
					continue
				}
				obs := observer.observe(ctx, target, p.Domain, run.knownHosts)
				if obs.redirect != nil {
					obs.redirect.ProfileID = p.ID
					obs.redirect.Host = normalizedHostname(target)
					obs.redirect.StatusCode = h.StatusCode
					obs.redirect.ObservedAt = time.Now().UTC()
				}
				select {
				case results <- result{obs.redirect, obs.reason != "" && obs.reason != "cross_host" && obs.reason != "cross_scope"}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(work)
		for _, h := range hosts {
			if redirectCode(h.StatusCode) {
				select {
				case work <- h:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	count, failures := 0, 0
	var storageErr error
	batch := make([]models.RedirectObservation, 0, 100)
	flush := func() {
		if len(batch) > 0 && storageErr == nil {
			_, storageErr = run.storeDirectoryObservations(p, nil, batch)
			if storageErr != nil {
				cancel()
			}
		}
		batch = batch[:0]
	}
	for result := range results {
		if result.failed {
			failures++
		}
		if result.redirect != nil {
			batch = append(batch, *result.redirect)
			count++
			if len(batch) == 100 {
				flush()
			}
		}
	}
	flush()
	if storageErr != nil {
		return count, storageErr
	}
	if ctx.Err() != nil {
		return count, ctx.Err()
	}
	if failures > 0 {
		return count, fmt.Errorf("%d root redirect observations incomplete", failures)
	}
	return count, nil
}
