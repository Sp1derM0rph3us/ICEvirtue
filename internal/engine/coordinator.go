package engine

import (
	"context"
	"errors"
	"fmt"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/jobs"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/wordlists"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"path/filepath"
	"sync"
	"time"
)

var ErrScanDuplicate = jobs.ErrDuplicate
var ErrQueueFull = jobs.ErrFull

const MaxQueuedScans = jobs.Capacity

type Coordinator struct {
	execute func(*runner, *models.Profile)
	db      *gorm.DB
	store   *wordlists.Store
	tools   *Toolchain
	Queue   *jobs.Queue
	Owner   string
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	done    chan struct{}
	start   sync.Once
}

func NewCoordinator(db *gorm.DB, store *wordlists.Store) *Coordinator {
	ctx, cancel := context.WithCancel(context.Background())
	return &Coordinator{db: db, store: store, tools: NewToolchain("", "", ""), Queue: &jobs.Queue{DB: db}, Owner: uuid.NewString(), ctx: ctx, cancel: cancel, done: make(chan struct{}), execute: func(r *runner, p *models.Profile) { r.result = r.OrchestrateScan(p) }}
}
func (c *Coordinator) SetTools(tools *Toolchain) { c.tools = tools }
func (c *Coordinator) Recover() error            { return c.Queue.Reap() }
func (c *Coordinator) Enqueue(id, source string) error {
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	return c.Queue.Enqueue(id, source)
}
func (c *Coordinator) Start() { c.start.Do(func() { go c.loop() }) }
func (c *Coordinator) loop() {
	defer close(c.done)
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	maintenance := time.NewTicker(15 * time.Second)
	defer maintenance.Stop()
	beat := time.NewTicker(10 * time.Second)
	defer beat.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	c.Queue.Heartbeat(c.Owner)
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-poll.C:
			if e := c.dispatch(); e != nil {
				logf("worker=%s dispatch: %v", c.Owner, e)
			}
		case <-maintenance.C:
			if e := c.Queue.Reap(); e != nil {
				logf("worker=%s recovery: %v", c.Owner, e)
			}
		case <-beat.C:
			if e := c.Queue.Heartbeat(c.Owner); e != nil {
				logf("worker=%s heartbeat: %v", c.Owner, e)
			}
		case <-prune.C:
			if e := c.Queue.Prune(); e != nil {
				logf("retention: %v", e)
			}
		}
	}
}
func (c *Coordinator) Stop() {
	c.cancel()
	c.Start()
	<-c.done
	c.wg.Wait()
	c.db.Where("id=?", c.Owner).Delete(&models.WorkerHeartbeat{})
}
func (c *Coordinator) dispatch() error {
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	claim, e := c.Queue.Claim(c.Owner)
	if e != nil || claim == nil {
		return e
	}
	ctx, cancel := context.WithCancel(c.ctx)
	r := &runner{ctx: ctx, FindingStore: NewFindingStore(c.db, claim.Job), executor: c.tools, tools: c.tools, config: claim.Config, wafTimeout: time.Duration(claim.Config.Tools.WAFTimeoutSeconds) * time.Second, result: Outcome{"completed", "completed"}}
	for _, selection := range []struct {
		rows []models.Wordlist
		out  *[]string
	}{{claim.DNSX, &r.dnsxPaths}, {claim.Directories, &r.directoryPaths}} {
		for _, w := range selection.rows {
			if c.store == nil || len(w.SHA256) != 64 || w.Filename != wordlists.Filename(w.SHA256, w.Kind) {
				cancel()
				return errors.Join(errors.New("invalid pinned wordlist"), c.Queue.Finish(claim.Job, "failed", "failed: pinned wordlist unavailable"))
			}
			*selection.out = append(*selection.out, filepath.Join(c.store.Path, w.Filename))
		}
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer cancel()
		renewalDone := make(chan struct{})
		go func() {
			defer close(renewalDone)
			tick := time.NewTicker(10 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if e := c.Queue.Renew(claim.Job); e != nil {
						cancel()
						return
					}
				}
			}
		}()
		defer func() {
			if v := recover(); v != nil {
				logf("run=%s panic: %v", claim.Job.RunID, v)
				r.result = Outcome{"failed", "failed: internal error"}
			}
			if ctx.Err() != nil {
				r.result = Outcome{"interrupted", "interrupted: worker stopped or lease lost"}
			}
			if e := c.Queue.Finish(claim.Job, r.result.Status, r.result.Summary); e != nil {
				logf("run=%s finalize: %v", claim.Job.RunID, e)
			}
			cancel()
			<-renewalDone
		}()
		cleanup, e := r.prepareScratch()
		if e != nil {
			r.result = Outcome{"failed", "failed: scratch storage unavailable"}
			return
		}
		defer cleanup()
		logf("worker=%s run=%s profile=%s revision=%d", c.Owner, claim.Job.RunID, claim.Job.ProfileID, claim.Config.Revision)
		c.execute(r, &claim.Profile)
		r.result = r.outcome(r.result)
	}()
	return nil
}
func (c *Coordinator) String() string { return fmt.Sprintf("scan worker %s", c.Owner) }
