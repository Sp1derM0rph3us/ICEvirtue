package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// These tests drive the real pipeline, including the real runTool and exec.LookPath
// path, by putting shell-script stand-ins for the recon tools at the front of PATH.
// Nothing is mocked and nothing touches the network, which means the partial-output
// and per-tool-failure behaviour is exercised exactly as it happens in production.

// fakeTool writes an executable stand-in for a tool. The body is a shell script,
// so it can emit output and then exit with any status.
//
// Every stub answers -version the way a goflags tool does, so it passes the
// identity probe in resolveTool. A stub that then fails its real invocation is
// therefore the right program failing, which is what these tests are about.
func fakeTool(t *testing.T, dir, name, body string) {
	t.Helper()

	path := filepath.Join(dir, name)
	script := "#!/bin/sh\n" +
		"case \"$1\" in -version) echo '[INF] Current Version: v9.9.9'; exit 0;; esac\n" +
		body + "\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatalf("writing fake %s: %v", name, err)
	}
}

// jsonlEmitter builds a script body that prints one JSON object per argument and
// then exits with the given status. Stdin is drained so upstream writers do not
// see a broken pipe.
func jsonlEmitter(exitCode int, lines ...string) string {
	body := "cat >/dev/null 2>&1\n"
	for _, l := range lines {
		body += fmt.Sprintf("printf '%%s\\n' '%s'\n", l)
	}
	return body + fmt.Sprintf("exit %d", exitCode)
}

func subfinderHosts(hosts ...string) []string {
	var lines []string
	for _, h := range hosts {
		lines = append(lines, fmt.Sprintf(`{"host":"%s","source":"test"}`, h))
	}
	return lines
}

func httpxHost(url string, status int) string {
	return fmt.Sprintf(`{"url":"%s","host":"h","a":["1.2.3.4"],"title":"t","webserver":"w","status_code":%d,"failed":false}`, url, status)
}

// newPipelineEnv gives the test an isolated PATH, an isolated tool home, an
// isolated SQLite database, and one profile to scan.
func newPipelineEnv(t *testing.T, mode string) (*models.Profile, string) {
	t.Helper()

	binDir := t.TempDir()
	t.Setenv("PATH", binDir)

	resetToolHome(t)
	// The resolution cache is process-global on purpose, so each test has to
	// clear it or it would reuse a binary path from a previous test's temp dir.
	resetToolPaths(t)
	ToolHome = t.TempDir()

	// Restore every pipeline flag the tests move around.
	prevFlags := []struct {
		p *bool
		v bool
	}{
		{&SkipAmass, SkipAmass}, {&SkipNuclei, SkipNuclei},
		{&WideTargets, WideTargets}, {&Verbose, Verbose},
	}
	prevDnsx, prevDirs := DnsxList, DirectoryList
	t.Cleanup(func() {
		for _, f := range prevFlags {
			*f.p = f.v
		}
		DnsxList, DirectoryList = prevDnsx, prevDirs
	})
	SkipAmass, SkipNuclei, WideTargets, Verbose = false, true, false, false
	DnsxList, DirectoryList = "", ""

	prevDB := database.DB
	t.Cleanup(func() { database.DB = prevDB })
	if err := database.InitDatabase(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDatabase: %v", err)
	}

	profile := &models.Profile{Domain: "example.com", Mode: mode, Schedule: "@every 24h", Enabled: true}
	if err := database.DB.Create(profile).Error; err != nil {
		t.Fatalf("creating profile: %v", err)
	}

	return profile, binDir
}

func countRows(t *testing.T, model interface{}, profileID interface{}) int64 {
	t.Helper()

	var n int64
	if err := database.DB.Model(model).Where("profile_id = ?", profileID).Count(&n).Error; err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	return n
}

func reloadProfile(t *testing.T, id interface{}) models.Profile {
	t.Helper()

	var p models.Profile
	if err := database.DB.First(&p, id).Error; err != nil {
		t.Fatalf("reloading profile: %v", err)
	}
	return p
}

// The headline behaviour: one discovery source failing must not cost us the others.
func TestDiscoveryContinuesWhenSubfinderFails(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "full")

	fakeTool(t, binDir, "subfinder", "echo 'open subfinder/config.yaml: no such file or directory'\nexit 1")
	fakeTool(t, binDir, "amass", jsonlEmitter(0, "a.example.com", "b.example.com", "c.example.com"))
	fakeTool(t, binDir, "httpx", jsonlEmitter(0, httpxHost("https://a.example.com", 200)))

	subdomains, report := stageDiscovery(profile)

	if len(subdomains) != 3 {
		t.Fatalf("got %d subdomains, want 3 from amass despite subfinder failing: %v", len(subdomains), subdomains)
	}
	if report.failed() != 1 {
		t.Errorf("failed() = %d, want 1", report.failed())
	}
	if report.productive() != 1 {
		t.Errorf("productive() = %d, want 1", report.productive())
	}
}

// A tool that streams results and then dies must not lose those results.
func TestDiscoveryKeepsPartialOutputFromAFailedTool(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "passive")

	// Three good JSONL lines, a truncated fourth, then a non-zero exit.
	fakeTool(t, binDir, "subfinder", jsonlEmitter(1, append(subfinderHosts("a.example.com", "b.example.com", "c.example.com"), `{"host":"trunca`)...))

	subdomains, report := stageDiscovery(profile)

	if len(subdomains) != 3 {
		t.Fatalf("got %d subdomains, want the 3 complete lines emitted before the failure: %v", len(subdomains), subdomains)
	}
	if report.failed() != 1 {
		t.Errorf("failed() = %d, want 1: the failure must still be reported", report.failed())
	}
	if report.productive() != 1 {
		t.Errorf("productive() = %d, want 1: a partial run that produced results is productive", report.productive())
	}
}

// Everything failing is the one case that legitimately halts, and it must be
// recorded on the profile.
func TestRunHaltsWhenEveryDiscoverySourceFails(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "full")

	fakeTool(t, binDir, "subfinder", "exit 1")
	fakeTool(t, binDir, "amass", "exit 1")

	OrchestrateScan(profile)

	if n := countRows(t, &models.Subdomain{}, profile.ID); n != 0 {
		t.Errorf("stored %d subdomains, want 0", n)
	}

	p := reloadProfile(t, profile.ID)
	if want := "halted: no subdomains found from any source"; p.LastScanStatus != want {
		t.Errorf("LastScanStatus = %q, want %q", p.LastScanStatus, want)
	}
	if p.IsScanning {
		t.Error("IsScanning must be cleared after a halt")
	}
	if p.LastScan.IsZero() {
		t.Error("LastScan must be recorded even when the run halts")
	}
}

// The requirement that motivated this change: halting must not discard what the
// earlier stages already collected.
func TestHaltAtValidationStillPersistsSubdomains(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "passive")

	fakeTool(t, binDir, "subfinder", jsonlEmitter(0, subfinderHosts("a.example.com", "b.example.com")...))
	fakeTool(t, binDir, "httpx", jsonlEmitter(0)) // answers nothing

	OrchestrateScan(profile)

	if n := countRows(t, &models.Subdomain{}, profile.ID); n != 2 {
		t.Errorf("stored %d subdomains, want 2 kept despite the halt", n)
	}
	if n := countRows(t, &models.AliveHost{}, profile.ID); n != 0 {
		t.Errorf("stored %d alive hosts, want 0", n)
	}

	p := reloadProfile(t, profile.ID)
	if want := "halted: no host answered HTTP"; p.LastScanStatus != want {
		t.Errorf("LastScanStatus = %q, want %q", p.LastScanStatus, want)
	}
}

// httpx dying partway through still leaves usable hosts, so the run continues.
func TestValidationPartialOutputKeepsRunAlive(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "passive")

	fakeTool(t, binDir, "subfinder", jsonlEmitter(0, subfinderHosts("a.example.com", "b.example.com")...))
	fakeTool(t, binDir, "httpx", jsonlEmitter(1, httpxHost("https://a.example.com", 200)))
	fakeTool(t, binDir, "gau", jsonlEmitter(0))

	OrchestrateScan(profile)

	if n := countRows(t, &models.AliveHost{}, profile.ID); n != 1 {
		t.Errorf("stored %d alive hosts, want the 1 confirmed before httpx failed", n)
	}

	p := reloadProfile(t, profile.ID)
	if want := "completed, httpx failed in Stage 02 Validation"; p.LastScanStatus != want {
		t.Errorf("LastScanStatus = %q, want %q", p.LastScanStatus, want)
	}
}

// A leaf stage can never halt the run, even when its tool is missing entirely.
func TestLeafStageFailureDoesNotHaltTheRun(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "passive")
	SkipNuclei = false // nuclei is deliberately absent from the fake PATH

	fakeTool(t, binDir, "subfinder", jsonlEmitter(0, subfinderHosts("a.example.com")...))
	fakeTool(t, binDir, "httpx", jsonlEmitter(0, httpxHost("https://a.example.com", 200)))

	OrchestrateScan(profile)

	p := reloadProfile(t, profile.ID)
	if !strings.HasPrefix(p.LastScanStatus, "completed") {
		t.Errorf("LastScanStatus = %q, want a completed status: a leaf stage must never halt the run", p.LastScanStatus)
	}
	// nuclei, gau, katana and subjs are all absent from the fake PATH, so the run
	// finished with failures recorded rather than being cut short.
	if !strings.Contains(p.LastScanStatus, "failed") {
		t.Errorf("LastScanStatus = %q, want the leaf failures noted", p.LastScanStatus)
	}
	if n := countRows(t, &models.AliveHost{}, profile.ID); n != 1 {
		t.Errorf("stored %d alive hosts, want 1", n)
	}
}

func TestWideTargetsControlsWhichHostsReachLeafStages(t *testing.T) {
	for _, tt := range []struct {
		name string
		wide bool
		want int
	}{
		{name: "default filter drops the 403", wide: false, want: 0},
		{name: "wide filter keeps the 403", wide: true, want: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			profile, binDir := newPipelineEnv(t, "passive")
			WideTargets = tt.wide

			fakeTool(t, binDir, "subfinder", jsonlEmitter(0, subfinderHosts("a.example.com")...))
			fakeTool(t, binDir, "httpx", jsonlEmitter(0, httpxHost("https://a.example.com", 403)))

			hosts, _ := stageValidation(profile, []string{"a.example.com"})
			if len(hosts) != 1 {
				t.Fatalf("got %d alive hosts, want 1", len(hosts))
			}

			if got := len(targetHosts(profile, hosts)); got != tt.want {
				t.Errorf("targetHosts() selected %d host(s), want %d", got, tt.want)
			}
		})
	}
}

// 404 must be excluded even under --wide-targets.
func TestWideTargetsStillExcludes404(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "passive")
	WideTargets = true

	fakeTool(t, binDir, "httpx", jsonlEmitter(0, httpxHost("https://dead.example.com", 404)))

	hosts, _ := stageValidation(profile, []string{"dead.example.com"})
	if got := len(targetHosts(profile, hosts)); got != 0 {
		t.Errorf("targetHosts() selected %d host(s), want 0", got)
	}
}

func TestSkippedToolsAreReportedAsSkippedNotFailed(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "full")
	SkipAmass = true

	fakeTool(t, binDir, "subfinder", jsonlEmitter(0, subfinderHosts("a.example.com")...))

	_, report := stageDiscovery(profile)

	if report.failed() != 0 {
		t.Errorf("failed() = %d, want 0: --skip-amass and a missing --dnsx-list are not failures", report.failed())
	}
	if report.attempted() != 1 {
		t.Errorf("attempted() = %d, want 1", report.attempted())
	}
	if note := report.failureNote(); note != "" {
		t.Errorf("failureNote() = %q, want empty", note)
	}
}

// A passive profile must not attempt the full-mode-only sources at all.
func TestPassiveProfileSkipsFullModeSources(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "passive")
	DnsxList = "/some/wordlist.txt"

	fakeTool(t, binDir, "subfinder", jsonlEmitter(0, subfinderHosts("a.example.com")...))
	fakeTool(t, binDir, "amass", "echo should-not-run.example.com")
	fakeTool(t, binDir, "dnsx", "echo should-not-run.example.com")

	subdomains, report := stageDiscovery(profile)

	if len(subdomains) != 1 {
		t.Errorf("got %v, want only the subfinder result", subdomains)
	}
	if report.attempted() != 1 {
		t.Errorf("attempted() = %d, want 1", report.attempted())
	}
}

func TestDnsxRunsOncePerWordlist(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "full")
	SkipAmass = true

	wlDir := t.TempDir()
	wl1, wl2 := filepath.Join(wlDir, "small.txt"), filepath.Join(wlDir, "big.txt")
	DnsxList = wl1 + ", " + wl2 + ","

	fakeTool(t, binDir, "subfinder", jsonlEmitter(0))
	// Each invocation emits a name derived from the wordlist it was handed.
	fakeTool(t, binDir, "dnsx", `for a in "$@"; do case "$a" in *small.txt) echo small.example.com;; *big.txt) echo big.example.com;; esac; done`)

	subdomains, report := stageDiscovery(profile)

	if len(subdomains) != 2 {
		t.Fatalf("got %v, want one result per wordlist", subdomains)
	}
	if report.attempted() != 3 {
		t.Errorf("attempted() = %d, want 3 (subfinder plus two dnsx runs)", report.attempted())
	}
	// The report must name which wordlist each run used.
	for _, want := range []string{"dnsx[small.txt]", "dnsx[big.txt]"} {
		found := false
		for _, r := range report.runs {
			if r.Tool == want {
				found = true
			}
		}
		if !found {
			t.Errorf("report has no entry for %s", want)
		}
	}
}

func TestCleanRunRecordsCompleted(t *testing.T) {
	profile, binDir := newPipelineEnv(t, "passive")

	fakeTool(t, binDir, "subfinder", jsonlEmitter(0, subfinderHosts("a.example.com")...))
	fakeTool(t, binDir, "httpx", jsonlEmitter(0, httpxHost("https://a.example.com", 200)))
	fakeTool(t, binDir, "gau", jsonlEmitter(0))
	fakeTool(t, binDir, "katana", jsonlEmitter(0))
	fakeTool(t, binDir, "subjs", jsonlEmitter(0))

	OrchestrateScan(profile)

	p := reloadProfile(t, profile.ID)
	if p.LastScanStatus != "completed" {
		t.Errorf("LastScanStatus = %q, want %q", p.LastScanStatus, "completed")
	}
	if p.IsScanning {
		t.Error("IsScanning must be cleared after the run")
	}
}
