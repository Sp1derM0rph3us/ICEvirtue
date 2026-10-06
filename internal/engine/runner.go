package engine

import (
	"context"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"sync"
	"time"
)

type runner struct {
	knownHosts    map[string]bool
	fuzzerSummary string
	ctx           context.Context
	*FindingStore
	executor ProcessExecutor
	errMu    sync.Mutex
	tools    *Toolchain

	config                    models.ApplicationConfiguration
	dnsxPaths, directoryPaths []string
	wafTimeout                time.Duration
	scratch                   string
	stageID                   uint
	storageErr                error
	result                    Outcome
}

func (r *runner) rememberStorageError(e error) {
	if e != nil {
		r.errMu.Lock()
		if r.storageErr == nil {
			r.storageErr = e
		}
		r.errMu.Unlock()
	}
}
func (r *runner) storageError() error { r.errMu.Lock(); defer r.errMu.Unlock(); return r.storageErr }
