package engine

import (
	"fmt"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"path/filepath"
	"strings"
)

func (run *runner) stageDiscovery(profile *models.Profile) ([]string, *stageReport) {
	report := newStageReport("Stage 01 Discovery", profile.Domain)

	unique := make(map[string]bool)
	var subdomains []string
	capped := false

	add := func(found []string) {
		for _, sub := range found {
			if sub != "" && !unique[sub] {
				if len(subdomains) >= 100000 {
					capped = true
					continue
				}
				unique[sub] = true
				subdomains = append(subdomains, sub)
			}
		}
	}

	subs, err := run.RunSubfinder(profile)
	add(subs)
	report.record("subfinder", len(subs), err)

	if profile.Mode != "full" {
		report.skip("amass", "profile is not in full mode")
		report.skip("dnsx", "profile is not in full mode")

		if capped {
			report.fail("discovery budget", len(subdomains), fmt.Errorf("100000 unique subdomain limit reached; partial results retained"))
		}
		report.Unique = len(subdomains)
		return subdomains, report
	}

	if run.config.Scan.SkipAmass {
		report.skip("amass", "disabled in application settings")
	} else {
		amassSubs, err := run.RunAmass(profile)
		add(amassSubs)
		report.record("amass", len(amassSubs), err)
	}

	wordlists := run.dnsxPaths
	if run.config.Scan.SkipDNSX || len(wordlists) == 0 {
		report.skip("dnsx", "DNSX is disabled or no wordlist selected")
	} else {
		for _, wlPath := range wordlists {
			dnsxSubs, err := run.RunDnsx(profile, wlPath)
			add(dnsxSubs)
			report.record(fmt.Sprintf("dnsx[%s]", filepath.Base(wlPath)), len(dnsxSubs), err)
		}
	}

	if capped {
		report.fail("discovery budget", len(subdomains), fmt.Errorf("100000 unique subdomain limit reached; partial results retained"))
	}
	report.Unique = len(subdomains)
	return subdomains, report
}

// stageValidation probes the discovered names and keeps the ones that answered.
// A partial httpx run still counts: whatever it confirmed alive is used.
func (run *runner) stageValidation(profile *models.Profile, subdomains []string) ([]models.AliveHost, *stageReport) {
	report := newStageReport("Stage 02 Validation", profile.Domain)

	hosts, err := run.RunHttpx(profile, subdomains)
	report.record("httpx", len(hosts), err)

	report.Unique = len(hosts)
	return hosts, report
}

// stageFuzzing walks the probe-worthy hosts with the built-in fuzzer.
func (run *runner) stageFuzzing(profile *models.Profile, targets []models.AliveHost) (int, *stageReport) {
	report := newStageReport("Stage 03 Directory Fuzzing", profile.Domain)

	wordlists := run.directoryPaths

	switch {
	case run.config.Scan.SkipDirectory || len(wordlists) == 0:
		report.skip("fuzzer", "directory discovery is disabled or no wordlist selected")
		return 0, report
	case len(targets) == 0:
		report.skip("fuzzer", "no probe-worthy hosts to fuzz")
		return 0, report
	}

	dirs, err := run.RunDirectoryFuzzing(profile, targets, wordlists)
	report.record("fuzzer", dirs, err)

	report.Unique = dirs
	return dirs, report
}

// stageVulns scans the probe-worthy hosts with nuclei.
func (run *runner) stageVulns(profile *models.Profile, targets []models.AliveHost) ([]models.Vulnerability, *stageReport) {
	report := newStageReport("Stage 04 Vulnerability Scanning", profile.Domain)

	switch {
	case run.config.Scan.SkipNuclei:
		report.skip("nuclei", "disabled in application settings")
		return nil, report
	case len(targets) == 0:
		report.skip("nuclei", "no probe-worthy hosts to scan")
		return nil, report
	}

	vulns, err := run.RunNuclei(profile, targets)
	report.record("nuclei", len(vulns), err)

	report.Unique = len(vulns)
	return vulns, report
}

// targetHosts decides which alive hosts are worth handing to stages 03 to 05.
//
// By default only hosts answering 200, 301, 302 or 307 qualify, which is the
// historical behaviour. With wide targets enabled everything httpx reported qualifies
// except a plain 404, on the grounds that a 403 or a 500 on / tells you nothing
// about what /admin returns, and finding exactly that is the point of fuzzing.
func (run *runner) targetHosts(profile *models.Profile, hosts []models.AliveHost) []models.AliveHost {
	var targets []models.AliveHost

	for _, h := range hosts {
		if run.config.Scan.WideTargets {
			if h.StatusCode != 404 {
				targets = append(targets, h)
			}
			continue
		}

		switch h.StatusCode {
		case 200, 301, 302, 307:
			targets = append(targets, h)
		}
	}

	policy := "default (200, 301, 302, 307)"
	if run.config.Scan.WideTargets {
		policy = "wide (any status except 404)"
	}
	logf("[*] [Target: %s] Target filter %s selected %d of %d alive host(s)",
		profile.Domain, policy, len(targets), len(hosts))

	return targets
}

// splitList parses a comma-separated flag value, dropping blank entries so a
// trailing comma is harmless.
func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
