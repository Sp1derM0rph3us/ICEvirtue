package engine

import (
	"context"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStreamingFuzzerDeduplicatesAndPersists(t *testing.T) {
	p, _ := newPipelineEnv(t, "passive")
	var mu sync.Mutex
	requests := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests[r.URL.Path]++
		mu.Unlock()
		if r.URL.Path != "/admin" && r.URL.Path != "/login" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
	os.WriteFile(a, []byte("admin\nadmin\n# ignored\n\n"), 0600)
	os.WriteFile(b, []byte("admin\nlogin\n"), 0600)
	run := testRunner()
	n, e := run.RunDirectoryFuzzing(p, []models.AliveHost{{URL: server.URL}}, []string{a, b})
	if e != nil || n != 2 {
		t.Fatalf("findings %d error %v", n, e)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests["/admin"] != 2 || requests["/login"] != 2 {
		t.Fatalf("not deduplicated: %v", requests)
	}
	var count int64
	testDB.Model(&models.DirectoryFinding{}).Where("profile_id = ?", p.ID).Count(&count)
	if count != 2 {
		t.Fatal("findings not persisted")
	}
}
func TestFuzzerCancellationStopsPreparation(t *testing.T) {
	p, _ := newPipelineEnv(t, "passive")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	run := testRunner()
	run.ctx = ctx
	if _, e := run.RunDirectoryFuzzing(p, nil, nil); e == nil {
		t.Fatal("cancelled fuzzing continued")
	}
}

func TestScratchChecksFilesystemAvailability(t *testing.T) {
	if err := checkScratch(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := checkScratch(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing scratch filesystem accepted")
	}
}

func TestDNSXUsesNormalizedPrivateCopy(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "upload"), filepath.Join(dir, "copy")
	raw := "# comment\r\n  www  \r\n\napi\n"
	os.WriteFile(source, []byte(raw), 0600)
	if err := testRunner().normalizeDNSXList(source, destination); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(destination)
	if string(data) != "www\napi\n" {
		t.Fatalf("normalization: %q", data)
	}
	data, _ = os.ReadFile(source)
	if string(data) != raw {
		t.Fatal("immutable upload changed")
	}
}
