package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/appconfig"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/wordlists"
	"gorm.io/gorm"
)

var ErrScanDuplicate = errors.New("profile already has a queued or running scan")
var ErrQueueFull = errors.New("scan queue is full")

const MaxQueuedScans = 100

type Coordinator struct {
	execute func(*runner, *models.Profile)
	db      *gorm.DB
	store   *wordlists.Store
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	done    chan struct{}
}

func NewCoordinator(db *gorm.DB, store *wordlists.Store) *Coordinator {
	ctx, cancel := context.WithCancel(context.Background())
	return &Coordinator{db: db, store: store, ctx: ctx, cancel: cancel, done: make(chan struct{}), execute: func(run *runner, p *models.Profile) { run.OrchestrateScan(p) }}
}
func (c *Coordinator) Recover() error {
	return c.db.Transaction(func(tx *gorm.DB) error {
		if e := tx.Model(&models.Profile{}).Where("is_scanning = ?", true).Updates(map[string]any{"is_scanning": false, "last_scan_status": "halted: interrupted by restart"}).Error; e != nil {
			return e
		}
		if e := tx.Where("state = ?", "running").Delete(&models.ScanJob{}).Error; e != nil {
			return e
		}
		if e := tx.Where("1 = 1").Delete(&models.WordlistPin{}).Error; e != nil {
			return e
		}
		if e := tx.Model(&models.Profile{}).Where("1 = 1").Update("is_queued", false).Error; e != nil {
			return e
		}
		return tx.Model(&models.Profile{}).Where("id IN (SELECT profile_id FROM scan_jobs WHERE state = ?)", "queued").Update("is_queued", true).Error
	})
}
func (c *Coordinator) Enqueue(id, source string) error {
	if c.ctx.Err() != nil {
		return errors.New("scan coordinator is shutting down")
	}
	err := c.db.Transaction(func(tx *gorm.DB) error {
		var p models.Profile
		if e := tx.First(&p, "id = ?", id).Error; e != nil {
			return e
		}
		if p.IsScanning || p.IsQueued {
			return ErrScanDuplicate
		}
		if source == "scheduled" && !p.Enabled {
			return errors.New("schedule disabled")
		}
		var n int64
		if e := tx.Model(&models.ScanJob{}).Where("state = ?", "queued").Count(&n).Error; e != nil {
			return e
		}
		if n >= MaxQueuedScans {
			return ErrQueueFull
		}
		if e := tx.Create(&models.ScanJob{ProfileID: id, Source: source, State: "queued"}).Error; e != nil {
			if errors.Is(e, gorm.ErrDuplicatedKey) {
				return ErrScanDuplicate
			}
			return e
		}
		return tx.Model(&p).Update("is_queued", true).Error
	})
	if err == nil {
		events.Broadcast("profile_update", id, nil)
	}
	return err
}
func (c *Coordinator) Start() {
	go func() {
		defer close(c.done)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				if err := c.dispatch(); err != nil {
					logf("[-] Scan queue: %v", err)
				}
			}
		}
	}()
}
func (c *Coordinator) Stop() { c.cancel(); <-c.done; c.wg.Wait() }
func (c *Coordinator) dispatch() error {
	var job models.ScanJob
	var p models.Profile
	var run *runner
	err := c.db.Transaction(func(tx *gorm.DB) error {
		settings, e := appconfig.Load(tx)
		if e != nil {
			return e
		}
		var active int64
		if e = tx.Model(&models.ScanJob{}).Where("state = ?", "running").Count(&active).Error; e != nil {
			return e
		}
		if active >= int64(settings.Tools.MaxConcurrentScans) {
			return nil
		}
		e = tx.Where("state = ?", "queued").Order("id ASC").First(&job).Error
		if errors.Is(e, gorm.ErrRecordNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		e = tx.First(&p, "id = ?", job.ProfileID).Error
		if errors.Is(e, gorm.ErrRecordNotFound) || (e == nil && job.Source == "scheduled" && !p.Enabled) {
			if e == nil {
				if e = tx.Model(&p).Update("is_queued", false).Error; e != nil {
					return e
				}
			}
			return tx.Delete(&job).Error
		}
		if e != nil {
			return e
		}
		if p.IsScanning {
			return nil
		}
		run = &runner{ctx: c.ctx, config: settings, wafTimeout: time.Duration(settings.Tools.WAFTimeoutSeconds) * time.Second, claimed: true}
		for _, selection := range []struct {
			ids   []string
			kind  string
			skip  bool
			paths *[]string
		}{{settings.Scan.DNSXWordlists, "subdomain", settings.Scan.SkipDNSX, &run.dnsxPaths}, {settings.Scan.DirectoryWordlists, "directory", settings.Scan.SkipDirectory, &run.directoryPaths}} {
			if selection.skip {
				continue
			}
			for _, id := range selection.ids {
				var w models.Wordlist
				if e = tx.First(&w, "id = ? AND state = ? AND kind = ?", id, "ready", selection.kind).Error; e != nil {
					return e
				}
				if w.Filename != wordlists.Filename(w.SHA256, w.Kind) || len(w.SHA256) != 64 {
					return errors.New("invalid stored wordlist name")
				}
				if c.store == nil {
					return errors.New("wordlist storage unavailable")
				}
				*selection.paths = append(*selection.paths, filepath.Join(c.store.Path, w.Filename))
				if e = tx.Create(&models.WordlistPin{JobID: job.ID, WordlistID: id}).Error; e != nil {
					return e
				}
			}
		}
		if e = tx.Model(&p).Updates(map[string]any{"is_scanning": true, "is_queued": false}).Error; e != nil {
			return e
		}
		return tx.Model(&job).Updates(map[string]any{"state": "running", "revision": settings.Revision}).Error
	})
	if err != nil || run == nil {
		return err
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer func() {
			if v := recover(); v != nil {
				logf("[-] Scan %s panicked: %v", job.ProfileID, v)
				c.db.Model(&p).Updates(map[string]any{"is_scanning": false, "last_scan_status": "halted: internal error"})
			}
			if e := c.db.Transaction(func(tx *gorm.DB) error {
				if e := tx.Model(&p).Update("is_scanning", false).Error; e != nil {
					return e
				}
				if e := tx.Where("job_id = ?", job.ID).Delete(&models.WordlistPin{}).Error; e != nil {
					return e
				}
				return tx.Delete(&job).Error
			}); e != nil {
				logf("[-] Releasing scan resources: %v", e)
			}
			events.Broadcast("profile_update", job.ProfileID, nil)
		}()
		logf("[*] Scan %s uses configuration revision %d", job.ProfileID, run.config.Revision)
		cleanup, err := run.prepareScratch()
		if err != nil {
			logf("[-] Preparing scan storage: %v", err)
			c.db.Model(&p).Update("last_scan_status", "halted: scratch storage unavailable")
			return
		}
		defer cleanup()
		c.execute(run, &p)
	}()
	return nil
}
func (c *Coordinator) String() string {
	return fmt.Sprintf("scan coordinator (queue capacity %d)", MaxQueuedScans)
}
