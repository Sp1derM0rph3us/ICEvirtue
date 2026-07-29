package engine

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetToolHome clears the memoised tool home so each test resolves it fresh,
// and restores the package globals afterwards. These tests mutate package state,
// so none of them may call t.Parallel.
func resetToolHome(t *testing.T) {
	t.Helper()

	origDefault := defaultToolHome
	origToolHome := ToolHome

	toolHomeOnce = sync.Once{}
	resolvedToolHome = ""

	// Clear systemd's directory variables so a test run that is itself under
	// systemd does not leak them into the candidate chain.
	t.Setenv("CACHE_DIRECTORY", "")
	t.Setenv("STATE_DIRECTORY", "")

	t.Cleanup(func() {
		toolHomeOnce = sync.Once{}
		resolvedToolHome = ""
		defaultToolHome = origDefault
		ToolHome = origToolHome
	})
}

// assertUsableToolHome checks the contract resolveToolHome promises: the
// directory exists and its .config subdirectory is genuinely writable.
func assertUsableToolHome(t *testing.T, dir string) {
	t.Helper()

	if dir == "" {
		t.Fatal("resolveToolHome returned an empty path")
	}
	if err := checkToolHome(dir); err != nil {
		t.Fatalf("resolveToolHome returned %q, which is not usable: %v", dir, err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".config")); err != nil {
		t.Fatalf("expected %q/.config to exist: %v", dir, err)
	}
}

func TestResolveToolHomeUsesExplicitFlag(t *testing.T) {
	resetToolHome(t)

	want := t.TempDir()
	ToolHome = want
	defaultToolHome = filepath.Join(t.TempDir(), "unused")

	got := resolveToolHome()
	if got != want {
		t.Errorf("resolveToolHome() = %q, want the --tool-home value %q", got, want)
	}
	assertUsableToolHome(t, got)
}

func TestResolveToolHomeUsesDefaultWhenNoFlag(t *testing.T) {
	resetToolHome(t)

	want := filepath.Join(t.TempDir(), "icevirtue")
	ToolHome = ""
	defaultToolHome = want

	got := resolveToolHome()
	if got != want {
		t.Errorf("resolveToolHome() = %q, want the default %q", got, want)
	}
	assertUsableToolHome(t, got)
}

func TestResolveToolHomeFallsBackToHomeWhenDefaultUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere, so the unwritable-default branch cannot be exercised")
	}
	resetToolHome(t)

	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	home := t.TempDir()
	ToolHome = ""
	defaultToolHome = filepath.Join(locked, "icevirtue")
	t.Setenv("HOME", home)

	got := resolveToolHome()
	if got != home {
		t.Errorf("resolveToolHome() = %q, want the $HOME fallback %q", got, home)
	}
	assertUsableToolHome(t, got)
}

// The systemd failure mode: no usable default and no $HOME. The tool home must
// still resolve to something writable rather than the empty string, because an
// empty HOME is exactly what makes subfinder exit 1 with no stderr.
func TestResolveToolHomeFallsBackToCwdWhenHomeUnset(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere, so the unwritable-default branch cannot be exercised")
	}
	resetToolHome(t)

	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	cwd := t.TempDir()
	t.Chdir(cwd)

	ToolHome = ""
	defaultToolHome = filepath.Join(locked, "icevirtue")
	t.Setenv("HOME", "")

	got := resolveToolHome()
	if want := filepath.Join(cwd, ".icevirtue-home"); got != want {
		t.Errorf("resolveToolHome() = %q, want the cwd fallback %q", got, want)
	}
	assertUsableToolHome(t, got)
}

func TestToolEnvForcesHomeAndXdgConfigHome(t *testing.T) {
	resetToolHome(t)

	home := t.TempDir()
	ToolHome = home
	t.Setenv("HOME", "/nonexistent-parent-home")
	t.Setenv("XDG_CONFIG_HOME", "/nonexistent-parent-xdg")

	var gotHome, gotXDG []string
	for _, kv := range toolEnv() {
		switch {
		case strings.HasPrefix(kv, "HOME="):
			gotHome = append(gotHome, strings.TrimPrefix(kv, "HOME="))
		case strings.HasPrefix(kv, "XDG_CONFIG_HOME="):
			gotXDG = append(gotXDG, strings.TrimPrefix(kv, "XDG_CONFIG_HOME="))
		}
	}

	// Exactly one of each: a duplicate would leave the resolved value at the
	// mercy of how the child's libc walks environ.
	if len(gotHome) != 1 || gotHome[0] != home {
		t.Errorf("HOME entries = %v, want exactly [%s]", gotHome, home)
	}
	wantXDG := filepath.Join(home, ".config")
	if len(gotXDG) != 1 || gotXDG[0] != wantXDG {
		t.Errorf("XDG_CONFIG_HOME entries = %v, want exactly [%s]", gotXDG, wantXDG)
	}
}

func TestRunToolMissingBinaryNamesToolAndPath(t *testing.T) {
	resetToolHome(t)
	ToolHome = t.TempDir()

	t.Setenv("PATH", "/nonexistent-bin-dir")

	_, err := runTool("definitely-not-a-real-tool", nil, nil, time.Minute)
	if err == nil {
		t.Fatal("expected an error for a binary that is not on PATH")
	}
	for _, want := range []string{"definitely-not-a-real-tool", "/nonexistent-bin-dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// The regression test for the reported bug. subfinder reports its config-directory
// failure on stdout and exits 1, leaving stderr empty; the old code reported only
// stderr, so the operator saw "Stderr:" followed by nothing.
func TestRunToolSurfacesStdoutOnFailure(t *testing.T) {
	resetToolHome(t)
	ToolHome = t.TempDir()

	_, err := runTool("sh", []string{"-c", "echo open subfinder/config.yaml: no such file or directory; exit 1"}, nil, time.Minute)
	if err == nil {
		t.Fatal("expected an error for a command that exits 1")
	}

	msg := err.Error()
	if !strings.Contains(msg, "open subfinder/config.yaml: no such file or directory") {
		t.Errorf("error does not include the message the tool printed to stdout:\n%s", msg)
	}
	if !strings.Contains(msg, "stderr: <empty>") {
		t.Errorf("error should say stderr was empty rather than printing nothing:\n%s", msg)
	}
	if !strings.Contains(msg, "exit status 1") {
		t.Errorf("error does not include the exit status:\n%s", msg)
	}
}

func TestRunToolSurfacesStderrOnFailure(t *testing.T) {
	resetToolHome(t)
	ToolHome = t.TempDir()

	_, err := runTool("sh", []string{"-c", "echo boom >&2; exit 2"}, nil, time.Minute)
	if err == nil {
		t.Fatal("expected an error for a command that exits 2")
	}
	if msg := err.Error(); !strings.Contains(msg, "boom") || !strings.Contains(msg, "exit status 2") {
		t.Errorf("error does not report the stderr message and exit status:\n%s", msg)
	}
}

// A timeout must kill the tool's whole process group and return promptly. If
// only the direct child is killed, a surviving grandchild holds the output pipe
// open and cmd.Wait blocks for the grandchild's full lifetime — so the timeout
// silently fails to bound anything.
func TestRunToolReportsTimeoutRatherThanSignalKilled(t *testing.T) {
	resetToolHome(t)
	ToolHome = t.TempDir()

	start := time.Now()
	_, err := runTool("sh", []string{"-c", "sleep 30"}, nil, 100*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the timeout fires")
	}
	if msg := err.Error(); !strings.Contains(msg, "timed out after 100ms") {
		t.Errorf("error should name the timeout, not just report a signal:\n%s", msg)
	}
	if elapsed > 5*time.Second {
		t.Errorf("runTool took %s to return after a 100ms timeout; the child's descendants were not killed", elapsed)
	}
}

func TestRunToolReturnsStdoutOnSuccess(t *testing.T) {
	resetToolHome(t)
	ToolHome = t.TempDir()

	out, err := runTool("sh", []string{"-c", "echo first; echo second"}, nil, time.Minute)
	if err != nil {
		t.Fatalf("runTool: %v", err)
	}
	if got, want := out.String(), "first\nsecond\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestRunToolPassesStdin(t *testing.T) {
	resetToolHome(t)
	ToolHome = t.TempDir()

	out, err := runTool("cat", nil, strings.NewReader("piped\n"), time.Minute)
	if err != nil {
		t.Fatalf("runTool: %v", err)
	}
	if got, want := out.String(), "piped\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

// runTool must hand the child a HOME it can actually write to even when the
// parent process has none, which is the situation systemd creates.
func TestRunToolGivesChildAWritableHome(t *testing.T) {
	resetToolHome(t)

	want := t.TempDir()
	ToolHome = want
	t.Setenv("HOME", "")

	out, err := runTool("sh", []string{"-c", `printf '%s' "$HOME"`}, nil, time.Minute)
	if err != nil {
		t.Fatalf("runTool: %v", err)
	}
	if got := out.String(); got != want {
		t.Errorf("child saw HOME=%q, want %q", got, want)
	}
}

func TestCappedBufferTruncatesAndReportsTheRemainder(t *testing.T) {
	c := &cappedBuffer{limit: 4}

	n, err := c.Write([]byte("abcdefgh"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Write must claim the full length or exec treats the short write as an error.
	if n != 8 {
		t.Errorf("Write returned n=%d, want 8", n)
	}
	if got, want := c.String(), "abcd ... (4 more bytes suppressed)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestCappedBufferKeepsShortOutputVerbatim(t *testing.T) {
	c := &cappedBuffer{limit: 64}

	if _, err := c.Write([]byte("short")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := c.String(); got != "short" {
		t.Errorf("String() = %q, want %q", got, "short")
	}
}

func TestDescribeStreamMarksEmptyOutput(t *testing.T) {
	if got := describeStream("  \n\t "); got != "<empty>" {
		t.Errorf("describeStream(whitespace) = %q, want %q", got, "<empty>")
	}
	if got := describeStream(" message \n"); got != "message" {
		t.Errorf("describeStream() = %q, want %q", got, "message")
	}
}

// Under a hardened unit (ProtectSystem=strict) systemd's CacheDirectory= and
// StateDirectory= are the only writable candidates, so they must be consulted
// before the paths that strict mode mounts read-only.
func TestResolveToolHomePrefersSystemdCacheDirectory(t *testing.T) {
	resetToolHome(t)

	cache := t.TempDir()
	ToolHome = ""
	defaultToolHome = "/proc/definitely-not-writable/icevirtue"
	t.Setenv("CACHE_DIRECTORY", cache)
	t.Setenv("STATE_DIRECTORY", t.TempDir())

	if got := resolveToolHome(); got != cache {
		t.Errorf("resolveToolHome() = %q, want CacheDirectory %q", got, cache)
	}
}

func TestResolveToolHomeFallsBackToStateDirectory(t *testing.T) {
	resetToolHome(t)

	state := t.TempDir()
	ToolHome = ""
	defaultToolHome = "/proc/definitely-not-writable/icevirtue"
	t.Setenv("CACHE_DIRECTORY", "")
	t.Setenv("STATE_DIRECTORY", state)

	if got := resolveToolHome(); got != state {
		t.Errorf("resolveToolHome() = %q, want StateDirectory %q", got, state)
	}
}

// An explicit --tool-home must still win over what systemd provides.
func TestResolveToolHomeExplicitFlagBeatsSystemdDirs(t *testing.T) {
	resetToolHome(t)

	explicit := t.TempDir()
	ToolHome = explicit
	t.Setenv("CACHE_DIRECTORY", t.TempDir())
	t.Setenv("STATE_DIRECTORY", t.TempDir())

	if got := resolveToolHome(); got != explicit {
		t.Errorf("resolveToolHome() = %q, want the --tool-home value %q", got, explicit)
	}
}

func TestSystemdDirsSplitsColonSeparatedList(t *testing.T) {
	t.Setenv("CACHE_DIRECTORY", "/a/one:/a/two")
	got := systemdDirs("CACHE_DIRECTORY")
	if len(got) != 2 || got[0] != "/a/one" || got[1] != "/a/two" {
		t.Errorf("systemdDirs() = %v, want [/a/one /a/two]", got)
	}
	t.Setenv("CACHE_DIRECTORY", "")
	if got := systemdDirs("CACHE_DIRECTORY"); got != nil {
		t.Errorf("systemdDirs() = %v, want nil for an unset value", got)
	}
}
