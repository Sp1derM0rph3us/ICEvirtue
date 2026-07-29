package engine

import (
	"fmt"
	"log"
	"sort"
	"strings"
)

// A stage is a group of tools that all contribute to one kind of finding. No
// individual tool inside a stage can stop the pipeline: the stage attempts every
// tool it can, aggregates whatever came back, persists it, and only then decides
// whether the run still has enough to continue.
//
// The corollary is that a stage may only halt the run when a later stage
// consumes its output. Fuzzing, vulnerability scanning and secret hunting are
// leaves, since nothing reads their findings, so they can never halt anything.

// toolRun records what a single tool contributed to a stage.
//
// Count can be greater than zero while Err is non-nil. A tool that streamed
// results and then died, or that was killed by its timeout partway through, has
// still contributed everything it managed to emit, and that output is kept.
type toolRun struct {
	Tool       string
	Count      int
	Err        error
	SkipReason string // non-empty when the tool was deliberately not attempted
}

func (r toolRun) skipped() bool { return r.SkipReason != "" }

// stageReport accumulates the outcome of every tool in one stage, plus the
// aggregate count after cross-tool de-duplication.
type stageReport struct {
	Stage  string
	Target string
	Unique int
	runs   []toolRun
}

func newStageReport(stage, target string) *stageReport {
	return &stageReport{Stage: stage, Target: target}
}

// ok records a tool that ran to completion.
func (s *stageReport) ok(tool string, count int) {
	s.runs = append(s.runs, toolRun{Tool: tool, Count: count})
}

// fail records a tool that errored. Pass whatever it produced before failing;
// those results are still merged into the stage output.
func (s *stageReport) fail(tool string, count int, err error) {
	s.runs = append(s.runs, toolRun{Tool: tool, Count: count, Err: err})
}

// skip records a tool that was not attempted, and why.
func (s *stageReport) skip(tool, reason string) {
	s.runs = append(s.runs, toolRun{Tool: tool, SkipReason: reason})
}

// record is the common shape at a call site: hand it the error from a Run*
// function together with whatever that function returned.
func (s *stageReport) record(tool string, count int, err error) {
	if err != nil {
		s.fail(tool, count, err)
		return
	}
	s.ok(tool, count)
}

// attempted counts the tools that were actually executed.
func (s *stageReport) attempted() int {
	n := 0
	for _, r := range s.runs {
		if !r.skipped() {
			n++
		}
	}
	return n
}

// succeeded counts the tools that executed without error.
func (s *stageReport) succeeded() int {
	n := 0
	for _, r := range s.runs {
		if !r.skipped() && r.Err == nil {
			n++
		}
	}
	return n
}

// failed counts the tools that errored, whether or not they produced results.
func (s *stageReport) failed() int {
	n := 0
	for _, r := range s.runs {
		if r.Err != nil {
			n++
		}
	}
	return n
}

// productive counts the tools that contributed at least one result, which is the
// number that decides whether a partially broken stage was still useful.
func (s *stageReport) productive() int {
	n := 0
	for _, r := range s.runs {
		if !r.skipped() && r.Count > 0 {
			n++
		}
	}
	return n
}

// Log writes a one-block summary: the stage headline followed by a line per
// tool, so a partially successful stage is legible at a glance.
func (s *stageReport) Log() {
	prefix := "[+]"
	if s.Unique == 0 {
		prefix = "[-]"
	}

	log.Printf("%s [Target: %s] %s: %d unique result(s) from %d of %d tool(s)",
		prefix, s.Target, s.Stage, s.Unique, s.productive(), s.attempted())

	width := 0
	for _, r := range s.runs {
		if len(r.Tool) > width {
			width = len(r.Tool)
		}
	}

	for _, r := range s.runs {
		switch {
		case r.skipped():
			log.Printf("      %-*s  skipped        %s", width, r.Tool, r.SkipReason)
		case r.Err != nil && r.Count > 0:
			log.Printf("      %-*s  PARTIAL   %5d  %v", width, r.Tool, r.Count, r.Err)
		case r.Err != nil:
			log.Printf("      %-*s  FAILED    %5d  %v", width, r.Tool, r.Count, r.Err)
		default:
			log.Printf("      %-*s  ok        %5d", width, r.Tool, r.Count)
		}
	}
}

// failureNote summarises tool failures for the profile's run status, naming the
// tools rather than quoting their output so the string stays short and safe to
// render in the dashboard. Returns "" when nothing failed.
func (s *stageReport) failureNote() string {
	var names []string
	for _, r := range s.runs {
		if r.Err != nil {
			names = append(names, r.Tool)
		}
	}
	if len(names) == 0 {
		return ""
	}

	sort.Strings(names)
	return fmt.Sprintf("%s failed in %s", strings.Join(names, ", "), s.Stage)
}
