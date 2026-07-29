package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetToolPaths clears the resolution cache and the override flag between tests.
func resetToolPaths(t *testing.T) {
	t.Helper()

	prev := ToolPaths
	toolPathMu.Lock()
	toolPathCache = map[string]resolution{}
	toolPathMu.Unlock()

	t.Cleanup(func() {
		ToolPaths = prev
		toolPathMu.Lock()
		toolPathCache = map[string]resolution{}
		toolPathMu.Unlock()
	})
	ToolPaths = ""
}

// writeStub puts an executable shell script named `name` in dir.
func writeStub(t *testing.T, dir, name, body string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatalf("writing stub %s: %v", name, err)
	}
	return path
}

// A goflags tool answers -version with exit 0 and a version number.
const realToolBody = `case "$1" in -version) echo "[INF] Current Version: v2.12.0"; exit 0;; esac
exit 0`

// python3-httpx owns the name httpx on Debian, Kali and Parrot, and rejects
// every flag the engine passes.
const imposterBody = `echo "Usage: httpx [OPTIONS] URL" >&2
echo "Error: No such option: -e" >&2
exit 2`

// The headline case: the name httpx resolves to the wrong program, while the
// real tool is installed under the Debian name. The engine must pick the real one.
func TestResolveToolSkipsImposterAndPicksVerifiedAlternative(t *testing.T) {
	resetToolPaths(t)
	resetToolHome(t)
	ToolHome = t.TempDir()

	bin := t.TempDir()
	t.Setenv("PATH", bin)
	writeStub(t, bin, "httpx", imposterBody)
	want := writeStub(t, bin, "httpx-toolkit", realToolBody)

	got, err := resolveTool("httpx")
	if err != nil {
		t.Fatalf("resolveTool: %v", err)
	}
	if got != want {
		t.Errorf("resolveTool(httpx) = %q, want the verified alternative %q", got, want)
	}
	if note := cachedToolNote("httpx"); note != "" {
		t.Errorf("a verified match must not be flagged as doubtful, got %q", note)
	}
}

// When the plain name is the real tool, the alternatives are never needed.
func TestResolveToolPrefersThePlainNameWhenItVerifies(t *testing.T) {
	resetToolPaths(t)
	resetToolHome(t)
	ToolHome = t.TempDir()

	bin := t.TempDir()
	t.Setenv("PATH", bin)
	want := writeStub(t, bin, "httpx", realToolBody)
	writeStub(t, bin, "httpx-toolkit", realToolBody)

	got, err := resolveTool("httpx")
	if err != nil {
		t.Fatalf("resolveTool: %v", err)
	}
	if got != want {
		t.Errorf("resolveTool(httpx) = %q, want %q", got, want)
	}
}

// If nothing verifies we still run, rather than refuse a possibly-working tool,
// but the doubt has to be recorded.
func TestResolveToolFallsBackWithADoubtfulNote(t *testing.T) {
	resetToolPaths(t)
	resetToolHome(t)
	ToolHome = t.TempDir()

	bin := t.TempDir()
	t.Setenv("PATH", bin)
	fallback := writeStub(t, bin, "httpx", imposterBody)

	got, err := resolveTool("httpx")
	if err != nil {
		t.Fatalf("resolveTool must not fail when a candidate exists: %v", err)
	}
	if got != fallback {
		t.Errorf("resolveTool(httpx) = %q, want the fallback %q", got, fallback)
	}

	note := cachedToolNote("httpx")
	if note == "" {
		t.Fatal("an unverified fallback must carry a note explaining the doubt")
	}
	for _, want := range []string{"-version", "--tool-paths"} {
		if !strings.Contains(note, want) {
			t.Errorf("note does not mention %q: %s", want, note)
		}
	}
}

// An explicit override skips discovery and probing entirely.
func TestResolveToolHonoursToolPathsOverride(t *testing.T) {
	resetToolPaths(t)
	resetToolHome(t)
	ToolHome = t.TempDir()

	bin := t.TempDir()
	t.Setenv("PATH", bin)
	writeStub(t, bin, "httpx", imposterBody)
	pinned := writeStub(t, t.TempDir(), "my-httpx", imposterBody) // deliberately fails the probe

	ToolPaths = "nuclei=/some/other, httpx=" + pinned

	got, err := resolveTool("httpx")
	if err != nil {
		t.Fatalf("resolveTool: %v", err)
	}
	if got != pinned {
		t.Errorf("resolveTool(httpx) = %q, want the pinned %q", got, pinned)
	}
	if note := cachedToolNote("httpx"); note != "" {
		t.Errorf("an explicit override must not be probed or flagged, got %q", note)
	}
}

func TestResolveToolReportsAnUnusableOverride(t *testing.T) {
	resetToolPaths(t)
	ToolPaths = "httpx=/nonexistent/httpx"

	_, err := resolveTool("httpx")
	if err == nil {
		t.Fatal("expected an error for an override that does not exist")
	}
	if !strings.Contains(err.Error(), "--tool-paths") {
		t.Errorf("error should name the flag at fault: %v", err)
	}
}

// A tool with no alternatives and nothing installed must name every name it tried.
func TestResolveToolMissingNamesEveryCandidate(t *testing.T) {
	resetToolPaths(t)
	t.Setenv("PATH", t.TempDir())

	_, err := resolveTool("httpx")
	if err == nil {
		t.Fatal("expected an error when nothing resolves")
	}
	for _, want := range []string{"httpx-toolkit", "httpx-pd"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention the alternative %q: %v", want, err)
		}
	}
}

// Unverified tools are located by name alone, with no probe.
func TestResolveToolDoesNotProbeUnverifiedTools(t *testing.T) {
	resetToolPaths(t)
	resetToolHome(t)
	ToolHome = t.TempDir()

	bin := t.TempDir()
	t.Setenv("PATH", bin)
	// Exits non-zero for everything, so it would fail a probe if one were run.
	want := writeStub(t, bin, "gau", "exit 3")

	got, err := resolveTool("gau")
	if err != nil {
		t.Fatalf("resolveTool: %v", err)
	}
	if got != want {
		t.Errorf("resolveTool(gau) = %q, want %q", got, want)
	}
	if note := cachedToolNote("gau"); note != "" {
		t.Errorf("gau must not be probed, got note %q", note)
	}
}

func TestVerifyToolIdentityRejectsMissingVersionNumber(t *testing.T) {
	resetToolHome(t)
	ToolHome = t.TempDir()

	// Exits 0 but prints no version, which is not a goflags tool.
	path := writeStub(t, t.TempDir(), "weird", `echo "hello there"; exit 0`)

	err := verifyToolIdentity(path)
	if err == nil {
		t.Fatal("expected rejection when no version number is printed")
	}
	if !strings.Contains(err.Error(), "no version number") {
		t.Errorf("unexpected reason: %v", err)
	}
}

func TestSummarizeOutputStripsAnsiAndTruncates(t *testing.T) {
	if got := summarizeOutput("\x1b[34m[INF]\x1b[0m  Current   Version: v1.0\n"); got != "[INF] Current Version: v1.0" {
		t.Errorf("summarizeOutput() = %q", got)
	}
	if got := summarizeOutput("   \n\t "); got != "<no output>" {
		t.Errorf("summarizeOutput(blank) = %q, want <no output>", got)
	}
	if got := summarizeOutput(strings.Repeat("x", 400)); len(got) != 163 {
		t.Errorf("summarizeOutput() length = %d, want 163 (160 + ellipsis)", len(got))
	}
}
