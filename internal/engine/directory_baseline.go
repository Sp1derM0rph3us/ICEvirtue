package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"path"
	"strings"
	"sync"
)

type baselineKey struct {
	scheme, host, port, parent, extension, query string
	slash                                        bool
}
type directoryBaseline struct {
	patterns []responseFingerprint
	requests int
}
type baselineEntry struct {
	ready chan struct{}
	value directoryBaseline
	users int
	used  uint64
}
type baselineCache struct {
	mu       sync.Mutex
	entries  map[baselineKey]*baselineEntry
	clock    uint64
	capacity int
}

func newBaselineCache(workers int) *baselineCache {
	return &baselineCache{entries: map[baselineKey]*baselineEntry{}, capacity: 2 * workers}
}
func contextKey(u *url.URL) baselineKey {
	slash := strings.HasSuffix(u.Path, "/")
	parent := path.Dir(strings.TrimSuffix(u.Path, "/"))
	if !strings.HasSuffix(parent, "/") {
		parent += "/"
	}
	ext := ""
	if !slash {
		ext = path.Ext(u.Path)
	}
	return baselineKey{u.Scheme, normalizedHostname(u), effectivePort(u), parent, ext, u.RawQuery, slash}
}
func (c *baselineCache) acquire(ctx context.Context, key baselineKey, calibrate func() directoryBaseline) (directoryBaseline, func(), bool) {
	c.mu.Lock()
	e, ok := c.entries[key]
	if !ok {
		e = &baselineEntry{ready: make(chan struct{})}
		c.entries[key] = e
	}
	e.users++
	c.mu.Unlock()
	release := func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		e.users--
		c.clock++
		e.used = c.clock
		c.evict()
	}
	if !ok {
		e.value = calibrate()
		close(e.ready)
	}
	select {
	case <-e.ready:
		value := e.value
		if ok {
			value.requests = 0
		}
		return value, release, true
	case <-ctx.Done():
		release()
		return directoryBaseline{}, func() {}, false
	}
}
func (c *baselineCache) evict() {
	for {
		unused := 0
		var oldest *baselineEntry
		var key baselineKey
		for k, e := range c.entries {
			if e.users == 0 {
				unused++
				if oldest == nil || e.used < oldest.used {
					oldest = e
					key = k
				}
			}
		}
		if unused <= c.capacity {
			return
		}
		delete(c.entries, key)
	}
}
func calibrateDirectory(ctx context.Context, o *directoryObserver, target *url.URL, domain string, known map[string]bool) directoryBaseline {
	key := contextKey(target)
	b := directoryBaseline{}
	var observations []directoryObservation
	for i := 0; i < 3; i++ {
		if ctx.Err() != nil {
			break
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			break
		}
		control := *target
		control.Path = key.parent + "icevirtue-missing-" + hex.EncodeToString(random[:]) + key.extension
		if key.slash {
			control.Path += "/"
		}
		control.RawPath = ""
		control.RawQuery = target.RawQuery
		control.Fragment = ""
		b.requests++
		observations = append(observations, o.observe(ctx, &control, domain, known))
	}
	for i, a := range observations {
		if a.reason != "" {
			continue
		}
		for j := i + 1; j < len(observations); j++ {
			other := observations[j]
			if other.reason == "" && fingerprintsMatch(a.fingerprint, other.fingerprint) {
				b.patterns = append(b.patterns, a.fingerprint)
				break
			}
		}
	}
	return b
}
func classifyDirectory(ctx context.Context, o *directoryObserver, cache *baselineCache, target *url.URL, domain string, known map[string]bool) (directoryObservation, string, string, int) {
	baseline, release, ok := cache.acquire(ctx, contextKey(target), func() directoryBaseline { return calibrateDirectory(ctx, o, target, domain, known) })
	defer release()
	if !ok {
		return directoryObservation{}, "", "canceled", 0
	}
	obs := o.observe(ctx, target, domain, known)
	if obs.initial == 0 {
		return obs, "", "request_failed", baseline.requests
	}
	if obs.terminal == 404 || obs.terminal == 410 || !directoryCode(obs.initial) {
		return obs, "", "rejected", baseline.requests
	}
	if obs.reason != "" {
		return obs, "unknown", obs.reason, baseline.requests
	}
	if !directoryCode(obs.terminal) || redirectCode(obs.terminal) {
		return obs, "", "rejected", baseline.requests
	}
	if len(baseline.patterns) == 0 {
		return obs, "unknown", "baseline_unstable", baseline.requests
	}
	for _, f := range baseline.patterns {
		if fingerprintsMatch(obs.fingerprint, f) {
			return obs, "unknown", "matches_missing_paths", baseline.requests
		}
	}
	repeated := o.observe(ctx, target, domain, known)
	if repeated.reason != "" || !fingerprintsMatch(obs.fingerprint, repeated.fingerprint) {
		return obs, "unknown", "response_unstable", baseline.requests
	}
	return obs, "confirmed", "distinct_from_missing_paths", baseline.requests
}
