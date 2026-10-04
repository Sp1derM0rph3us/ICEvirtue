package engine

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

var errScratchLimit = errors.New("scan scratch storage limit reached")

// minScratchFreeBytes is the free-space floor on the scratch filesystem below
// which a scan is halted to protect the host.
const minScratchFreeBytes = 64 << 20

// External tools write files themselves. Monitor the whole scan directory in
// addition to enforcing write/page limits on storage owned by Go.
func (run *runner) prepareScratch() (func(), error) {
	dir, err := os.MkdirTemp("", "icevirtue-scan-")
	if err != nil {
		return nil, err
	}
	run.scratch = dir
	ctx, cancel := context.WithCancelCause(run.ctx)
	run.ctx = ctx
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if e := checkScratch(dir); e != nil {
					cancel(e)
					return
				}
			}
		}
	}()
	return func() { cancel(nil); <-done; os.RemoveAll(dir) }, nil
}

// checkScratch halts a scan only when the scratch filesystem is genuinely
// almost full. Per-tool output budgets (see maxToolOutputBytes in exec.go)
// bound each captured stream, so a single verbose tool no longer needs a
// scan-wide aggregate byte cap here: this is purely the disk-exhaustion net.
func checkScratch(dir string) error {
	var disk syscall.Statfs_t
	if err := syscall.Statfs(dir, &disk); err != nil {
		return err
	}
	if disk.Bavail*uint64(disk.Bsize) < minScratchFreeBytes {
		return errScratchLimit
	}
	return nil
}
