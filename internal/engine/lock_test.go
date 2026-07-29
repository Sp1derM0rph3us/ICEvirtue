package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// These tests cover the scan lock rather than the pipeline. They reuse
// newPipelineEnv, so PATH holds nothing but the stubs the test installs and no
// real recon tool is ever reached.

// recordingTool installs a stub that appends one line to a marker file every
// time it is invoked for real, then lingers so concurrent callers overlap.
//
// Counting invocations is what makes the difference between "the lock was
// claimed once" and "the lock was claimed twice" observable: a second pipeline
// run cannot happen without a second subfinder execution. The -version probe
// that resolveTool performs is answered by fakeTool before this body runs, so it
// is not counted.
//
// sleep is called by absolute path on purpose. newPipelineEnv replaces PATH with
// the stub directory, so a bare `sleep` would not resolve inside the script.
func recordingTool(t *testing.T, binDir, marker string, lingerSeconds int) {
	t.Helper()

	fakeTool(t, binDir, "subfinder", fmt.Sprintf(
		"cat >/dev/null 2>&1\nprintf 'run\\n' >> %s\n/bin/sleep %d\nexit 0",
		marker, lingerSeconds))
}

func invocations(t *testing.T, marker string) int {
	t.Helper()

	data, err := os.ReadFile(marker)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("reading invocation marker: %v", err)
	}
	return len(strings.Fields(string(data)))
}

// TestConcurrentScansClaimTheLockExactlyOnce is the regression test for the
// read-then-write scan lock.
//
// OrchestrateScan used to load the profile, test IsScanning, and only then set
// it, which left a window in which two callers both saw false and both ran the
// entire pipeline against one profile. Releasing every caller from one barrier
// so they contend simultaneously, then asserting the pipeline started once, is
// what detects that window. The stub lingers for two seconds, which is far
// longer than the scheduling latency of the goroutines being released, so a late
// starter cannot legitimately win a second run and make this flaky.
func TestConcurrentScansClaimTheLockExactlyOnce(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "passive")

	marker := filepath.Join(t.TempDir(), "invocations")
	recordingTool(t, binDir, marker, 2)

	const callers = 25
	var release sync.WaitGroup
	var done sync.WaitGroup
	release.Add(1)

	for range callers {
		done.Add(1)
		go func() {
			defer done.Done()
			release.Wait()
			OrchestrateScan(profile)
		}()
	}

	release.Done()
	done.Wait()

	if got := invocations(t, marker); got != 1 {
		t.Fatalf("expected exactly 1 pipeline run from %d concurrent callers, got %d", callers, got)
	}

	// The lock has to be released even though the run halted at discovery, or the
	// profile would stay stuck in the scanning state forever.
	if p := reloadProfile(t, profile.ID); p.IsScanning {
		t.Error("is_scanning is still set after every caller returned")
	}
}

// TestScanIsRefusedWhileAnotherIsRunning covers the loser path deterministically:
// with the lock already held, no pipeline may start at all.
func TestScanIsRefusedWhileAnotherIsRunning(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "passive")

	marker := filepath.Join(t.TempDir(), "invocations")
	recordingTool(t, binDir, marker, 0)

	if err := database.DB.Model(&models.Profile{}).
		Where("id = ?", profile.ID).
		Update("is_scanning", true).Error; err != nil {
		t.Fatalf("seeding the scan lock: %v", err)
	}

	OrchestrateScan(profile)

	if got := invocations(t, marker); got != 0 {
		t.Fatalf("expected no pipeline run while the lock was held, got %d", got)
	}

	// A refused caller must not clear a lock it never owned, otherwise it would
	// unlock the run that is genuinely in progress.
	if p := reloadProfile(t, profile.ID); !p.IsScanning {
		t.Error("a refused caller released the scan lock held by another run")
	}
}

// TestScanRunsAgainAfterTheLockIsReleased guards against the opposite mistake:
// a lock that is claimed atomically but never freed would let one run poison the
// profile permanently.
func TestScanRunsAgainAfterTheLockIsReleased(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "passive")

	marker := filepath.Join(t.TempDir(), "invocations")
	recordingTool(t, binDir, marker, 0)

	OrchestrateScan(profile)
	OrchestrateScan(profile)

	if got := invocations(t, marker); got != 2 {
		t.Fatalf("expected 2 sequential runs to both execute, got %d", got)
	}
}
