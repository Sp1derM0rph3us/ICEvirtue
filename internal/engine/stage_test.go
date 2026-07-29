package engine

import (
	"errors"
	"strings"
	"testing"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func TestStageReportCountsPartialSuccess(t *testing.T) {
	r := newStageReport("Stage 01 Discovery", "example.com")
	r.ok("subfinder", 3987)
	r.fail("amass", 0, errors.New("amass not found"))
	r.fail("dnsx[wl1]", 12, errors.New("timed out after 30m")) // died with results in hand
	r.skip("dnsx[wl2]", "wordlist unreadable")
	r.Unique = 3999

	if got, want := r.attempted(), 3; got != want {
		t.Errorf("attempted() = %d, want %d (the skipped tool must not count)", got, want)
	}
	if got, want := r.succeeded(), 1; got != want {
		t.Errorf("succeeded() = %d, want %d", got, want)
	}
	if got, want := r.failed(), 2; got != want {
		t.Errorf("failed() = %d, want %d", got, want)
	}
	// The partial dnsx run counts as productive: it handed back real results.
	if got, want := r.productive(), 2; got != want {
		t.Errorf("productive() = %d, want %d", got, want)
	}
}

func TestStageReportFailureNoteNamesToolsAlphabetically(t *testing.T) {
	r := newStageReport("Stage 01 Discovery", "example.com")
	r.fail("subfinder", 0, errors.New("boom"))
	r.ok("amass", 5)
	r.fail("dnsx", 0, errors.New("boom"))

	got := r.failureNote()
	if want := "dnsx, subfinder failed in Stage 01 Discovery"; got != want {
		t.Errorf("failureNote() = %q, want %q", got, want)
	}
}

func TestStageReportFailureNoteEmptyWhenNothingFailed(t *testing.T) {
	r := newStageReport("Stage 02 Validation", "example.com")
	r.ok("httpx", 12)
	r.skip("nuclei", "--skip-nuclei was passed")

	if got := r.failureNote(); got != "" {
		t.Errorf("failureNote() = %q, want empty", got)
	}
}

// The note must name tools, never quote their output, because it ends up in a
// dashboard table cell.
func TestStageReportFailureNoteExcludesToolOutput(t *testing.T) {
	r := newStageReport("Stage 01 Discovery", "example.com")
	r.fail("subfinder", 0, errors.New("subfinder failed after 26ms (exit status 1)\n  stdout: open /root/.config/subfinder/config.yaml: no such file"))

	if note := r.failureNote(); strings.Contains(note, "config.yaml") || strings.Contains(note, "\n") {
		t.Errorf("failureNote() leaked tool output: %q", note)
	}
}

func TestRunStatusSummary(t *testing.T) {
	tests := []struct {
		name string
		set  func(*runStatus)
		want string
	}{
		{
			name: "clean run",
			set:  func(s *runStatus) {},
			want: "completed",
		},
		{
			name: "one tool failed",
			set: func(s *runStatus) {
				r := newStageReport("Stage 01 Discovery", "example.com")
				r.fail("amass", 0, errors.New("boom"))
				s.noteFailures(r)
			},
			want: "completed, amass failed in Stage 01 Discovery",
		},
		{
			name: "several stages had failures",
			set: func(s *runStatus) {
				for _, stage := range []string{"Stage 01 Discovery", "Stage 04 Vulnerability Scanning"} {
					r := newStageReport(stage, "example.com")
					r.fail("tool", 0, errors.New("boom"))
					s.noteFailures(r)
				}
			},
			want: "completed, 2 tools failed",
		},
		{
			name: "halted wins over failures",
			set: func(s *runStatus) {
				r := newStageReport("Stage 01 Discovery", "example.com")
				r.fail("subfinder", 0, errors.New("boom"))
				s.noteFailures(r)
				s.halt("no subdomains found from any source")
			},
			want: "halted: no subdomains found from any source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &runStatus{}
			tt.set(s)
			if got := s.summary(); got != tt.want {
				t.Errorf("summary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTargetHostsDefaultFilter(t *testing.T) {
	prev := WideTargets
	t.Cleanup(func() { WideTargets = prev })
	WideTargets = false

	hosts := hostsWithStatus(200, 301, 302, 307, 401, 403, 404, 405, 500, 503)
	got := statusCodesOf(targetHosts(&models.Profile{Domain: "example.com"}, hosts))

	want := []int{200, 301, 302, 307}
	if !equalInts(got, want) {
		t.Errorf("targetHosts() selected %v, want %v", got, want)
	}
}

func TestTargetHostsWideFilterExcludesOnly404(t *testing.T) {
	prev := WideTargets
	t.Cleanup(func() { WideTargets = prev })
	WideTargets = true

	hosts := hostsWithStatus(200, 301, 302, 307, 401, 403, 404, 405, 500, 503)
	got := statusCodesOf(targetHosts(&models.Profile{Domain: "example.com"}, hosts))

	want := []int{200, 301, 302, 307, 401, 403, 405, 500, 503}
	if !equalInts(got, want) {
		t.Errorf("targetHosts() selected %v, want %v", got, want)
	}
}

func TestTargetHostsHandlesNoHosts(t *testing.T) {
	if got := targetHosts(&models.Profile{Domain: "example.com"}, nil); len(got) != 0 {
		t.Errorf("targetHosts(nil) = %v, want empty", got)
	}
}

func TestSplitList(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{",,,", nil},
		{"/a/wl1", []string{"/a/wl1"}},
		{"/a/wl1,/a/wl2", []string{"/a/wl1", "/a/wl2"}},
		{" /a/wl1 , /a/wl2 ,", []string{"/a/wl1", "/a/wl2"}}, // trailing comma is harmless
	}

	for _, tt := range tests {
		got := splitList(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("splitList(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitList(%q) = %v, want %v", tt.in, got, tt.want)
				break
			}
		}
	}
}

func hostsWithStatus(codes ...int) []models.AliveHost {
	var hosts []models.AliveHost
	for _, c := range codes {
		hosts = append(hosts, models.AliveHost{URL: "https://h.example.com", StatusCode: c})
	}
	return hosts
}

func statusCodesOf(hosts []models.AliveHost) []int {
	var codes []int
	for _, h := range hosts {
		codes = append(codes, h.StatusCode)
	}
	return codes
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
