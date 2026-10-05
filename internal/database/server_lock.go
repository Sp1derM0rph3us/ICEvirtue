package database

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// LockServer serializes server migrations and upload reconciliation.
// Scan workers and administrative CLI access remain available.
func LockServer(dbPath string) (func(), error) {
	path, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".server.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another ICEvirtue server holds this database: %w", err)
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
