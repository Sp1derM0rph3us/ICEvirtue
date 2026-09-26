package serverlogs

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestLogBufferBoundsAndSnapshot(t *testing.T) {
	b := &Buffer{}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 600; j++ {
				b.Write([]byte(fmt.Sprintf("worker %d entry %d", worker, j)))
			}
		}(i)
	}
	wg.Wait()
	if len(b.Snapshot()) != Capacity {
		t.Fatal("buffer not bounded")
	}
	b.Write([]byte(strings.Repeat("x", MaxEntryBytes+100)))
	result := b.Snapshot()
	if !strings.HasSuffix(result[0].Message, "[truncated]") {
		t.Fatal("entry not bounded")
	}
	result[0].Message = "mutated"
	if b.Snapshot()[0].Message == "mutated" {
		t.Fatal("snapshot aliases storage")
	}
}
