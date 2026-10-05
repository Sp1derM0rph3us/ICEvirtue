package engine

import (
	"context"
	"errors"
	"fmt"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type Outcome struct{ Status, Summary string }

func haltReasonFor(ctx context.Context) string {
	if errors.Is(context.Cause(ctx), errScratchLimit) {
		return "scratch storage limit reached"
	}
	return "interrupted"
}
func (run *runner) OrchestrateScan(p *models.Profile) Outcome {
	outcome := Outcome{"completed", "completed"}
	status := &runStatus{}
	stop := func() bool { return run.ctx.Err() != nil }
	stage := func(name string, input int, fn func() (*stageReport, int, error)) bool {
		if stop() {
			return false
		}
		if err := run.beginStage(name, input); err != nil {
			outcome = Outcome{"failed", "failed: cannot record scan stage"}
			return false
		}
		report, stored, err := fn()
		report.Log()
		if err == nil {
			err = run.storageError()
		}
		if e := run.endStage(report, stored, err); err == nil {
			err = e
		}
		if err != nil {
			outcome = Outcome{"failed", "failed: finding storage or stage recording"}
			return false
		}
		status.noteFailures(report)
		return !stop()
	}
	var subs []string
	if !stage("discovery", 0, func() (*stageReport, int, error) {
		var r *stageReport
		subs, r = run.stageDiscovery(p)
		n, e := run.persistSubdomains(p, subs)
		return r, n, e
	}) {
		return run.outcome(outcome)
	}
	if len(subs) == 0 {
		return Outcome{"halted", "halted: no subdomains found from any source"}
	}
	var hosts []models.AliveHost
	if !stage("validation", len(subs), func() (*stageReport, int, error) {
		var r *stageReport
		hosts, r = run.stageValidation(p, subs)
		n, e := run.persistHosts(p, hosts)
		if e != nil {
			return r, n, e
		}
		if run.config.Scan.SkipWAF {
			r.skip("wafw00f", "disabled in application settings")
		} else if len(hosts) == 0 {
			r.skip("wafw00f", "no HTTP-responsive endpoints")
		} else {
			w, err := run.RunWAFDetection(hosts)
			r.record("wafw00f", len(w), err)
			added, err := run.persistWAFs(p, w)
			n += added
			if err != nil {
				return r, n, err
			}
		}
		return r, n, nil
	}) {
		return run.outcome(outcome)
	}
	if len(hosts) == 0 {
		return Outcome{"halted", "halted: no host answered HTTP"}
	}
	targets := run.targetHosts(p, hosts)
	if !stage("directories", len(targets), func() (*stageReport, int, error) {
		n, r := run.stageFuzzing(p, targets)
		return r, n, run.storageError()
	}) {
		return run.outcome(outcome)
	}
	if !stage("vulnerabilities", len(targets), func() (*stageReport, int, error) {
		v, r := run.stageVulns(p, targets)
		n, e := run.persistVulns(p, v)
		return r, n, e
	}) {
		return run.outcome(outcome)
	}
	if !stage("secrets", len(targets), func() (*stageReport, int, error) {
		v, r := run.stageSecrets(p, targets)
		n, e := run.persistSecrets(p, v)
		return r, n, e
	}) {
		return run.outcome(outcome)
	}
	if len(status.failures) > 0 {
		outcome = Outcome{"completed_with_errors", status.summary()}
	}
	return run.outcome(outcome)
}
func (run *runner) outcome(o Outcome) Outcome {
	if run.ctx.Err() != nil {
		return Outcome{"interrupted", "interrupted: " + haltReasonFor(run.ctx)}
	}
	return o
}

// runStatus accumulates what to record on the profile once the run ends, so a
// halt is visible on the dashboard and not only in the service log.
type runStatus struct {
	halted     bool
	haltReason string
	failures   []string
}

func (r *runStatus) halt(reason string) {
	r.halted = true
	r.haltReason = reason
}

func (r *runStatus) noteFailures(report *stageReport) {
	if note := report.failureNote(); note != "" {
		r.failures = append(r.failures, note)
	}
}

// summary is the short, controlled string stored on the profile. It deliberately
// never carries raw tool output, both to stay readable in a table cell and
// because it is rendered in the dashboard.
func (r *runStatus) summary() string {
	if r.halted {
		return "halted: " + r.haltReason
	}

	switch len(r.failures) {
	case 0:
		return "completed"
	case 1:
		return "completed, " + r.failures[0]
	default:
		return fmt.Sprintf("completed, %d tools failed", len(r.failures))
	}
}
