// Package serverlogs retains a bounded, concurrency-safe tail of process logs.
package serverlogs

import (
	"strings"
	"sync"
	"time"
)

const Capacity = 2000
const MaxEntryBytes = 16384

type Entry struct {
	Time    time.Time
	Message string
}
type Buffer struct {
	mu      sync.RWMutex
	entries []Entry
}

var Default = &Buffer{}

func (b *Buffer) Write(p []byte) (int, error) {
	message := strings.TrimSpace(string(p))
	if len(message) > MaxEntryBytes {
		message = message[:MaxEntryBytes] + " [truncated]"
	}
	if message == "" {
		return len(p), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) == Capacity {
		copy(b.entries, b.entries[1:])
		b.entries = b.entries[:Capacity-1]
	}
	b.entries = append(b.entries, Entry{Time: time.Now().UTC(), Message: message})
	return len(p), nil
}

func (b *Buffer) Snapshot() []Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Entry, len(b.entries))
	for i := range b.entries {
		out[len(out)-1-i] = b.entries[i]
	}
	return out
}
