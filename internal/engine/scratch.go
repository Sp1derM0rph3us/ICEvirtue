package engine

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var errScratchLimit = errors.New("scan scratch storage limit reached")

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
				if e := checkScratch(dir, fuzzScratchBytes); e != nil {
					cancel(e)
					return
				}
			}
		}
	}()
	return func() { cancel(nil); <-done; os.RemoveAll(dir) }, nil
}
func checkScratch(dir string, limit int64) error {
	var total int64
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		total += info.Size()
		if total > limit {
			return errScratchLimit
		}
		return nil
	})
	if err != nil {
		return err
	}
	var disk syscall.Statfs_t
	if err = syscall.Statfs(dir, &disk); err != nil {
		return err
	}
	if disk.Bavail*uint64(disk.Bsize) < 64<<20 {
		return errScratchLimit
	}
	return nil
}
