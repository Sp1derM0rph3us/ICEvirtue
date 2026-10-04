package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/hostkey"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/notifications"
)

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

// OrchestrateScan runs the full pipeline for one profile.
//
// Halt decisions are made per stage rather than per tool. Every stage attempts
// every tool it can, merges whatever came back, persists it, and only then asks
// whether the run still has enough to continue. A stage may only halt the run
// when a later stage consumes its output, which means discovery and validation
// can halt while fuzzing, vulnerability scanning and secret hunting cannot: they
// are leaves, so they either run or are skipped with a logged reason.
func (run *runner) OrchestrateScan(profile *models.Profile) {
	var p models.Profile
	if err := database.DB.First(&p, profile.ID).Error; err != nil {
		logf("[-] Profile %s not found in DB before scan", profile.ID)
		return
	}

	// Work from the freshly loaded row for the rest of the pipeline. The caller's
	// copy is captured when the scan is triggered and goes stale if the profile's
	// Domain or Mode is edited before the scan actually starts.
	profile = &p

	// Claim the scan lock atomically.
	//
	// Reading is_scanning and then writing it left a window in which two triggers
	// — a forced scan racing its own schedule, or two API calls arriving together
	// — both saw false and both proceeded, running the whole pipeline twice
	// against one profile. Making the database arbitrate with a conditional
	// UPDATE closes that window: exactly one caller can observe RowsAffected == 1.
	if !run.claimed {
		claim := database.DB.Model(&models.Profile{}).
			Where("id = ? AND is_scanning = ?", p.ID, false).
			Update("is_scanning", true)
		if claim.Error != nil {
			logf("[-] Failed to acquire the scan lock for %s: %v", p.Domain, claim.Error)
			return
		}
		if claim.RowsAffected == 0 {
			logf("[-] Skipping scan for %s. A scan is already currently running.", p.Domain)
			return
		}

	}
	events.Broadcast("profile_update", p.ID.String(), nil)
	notifications.Create(notifications.ScanStarted, "Scan started",
		profile.Domain+" · running in the background", "", &p.ID)

	status := &runStatus{}
	defer func() {
		if run.ctx.Err() != nil {
			status.halt(haltReasonFor(run.ctx))
		}
		database.DB.Model(&p).Updates(map[string]interface{}{
			"is_scanning":      false,
			"last_scan":        time.Now().UTC(),
			"last_scan_status": status.summary(),
		})
		events.Broadcast("profile_update", p.ID.String(), nil)
	}()

	logf("======================")
	logf("[+] INITIATING SCAN PIPELINE for Profile: %s", profile.Domain)
	logf("======================")

	// Stage 01. Halting here means no source produced anything, so there is no
	// attack surface to enumerate and the target itself is suspect.
	subdomains, discovery := run.stageDiscovery(profile)
	discovery.Log()
	status.noteFailures(discovery)
	newSubdomains := run.persistSubdomains(profile, subdomains)

	if len(subdomains) == 0 {
		status.halt("no subdomains found from any source")
		logf("[-] [Target: %s] Halting run: every discovery source failed or came back empty. Check the target domain is spelled correctly.", profile.Domain)
		notifications.Create(notifications.ScanHalted, "Scan halted",
			profile.Domain+" · no subdomains found from any source", "", &p.ID)
		return
	}

	// Stage 02. Halting here means nothing answered, so no later stage has a
	// host to work with. The subdomains above are already saved.
	hosts, validation := run.stageValidation(profile, subdomains)
	newHosts := run.persistHosts(profile, hosts)
	changedWAFs := 0
	if run.config.Scan.SkipWAF {
		validation.skip("wafw00f", "disabled in application settings")
	} else if len(hosts) == 0 {
		validation.skip("wafw00f", "no HTTP-responsive endpoints")
	} else {
		wafs, wafErr := run.RunWAFDetection(hosts)
		validation.record("wafw00f", len(wafs), wafErr)
		changedWAFs = run.persistWAFs(profile, wafs)
	}
	validation.Log()
	status.noteFailures(validation)

	if len(hosts) == 0 {
		status.halt("no host answered HTTP")
		logf("[-] [Target: %s] Halting run: none of the %d discovered subdomains answered HTTP, so nothing downstream can execute.", profile.Domain, len(subdomains))
		logf("[+] [Target: %s] Persisted %d subdomain(s), %d new.", profile.Domain, len(subdomains), newSubdomains)
		notifications.Create(notifications.ScanHalted, "Scan halted",
			profile.Domain+" · no host answered HTTP", "", &p.ID)
		return
	}

	targets := run.targetHosts(profile, hosts)

	// Stages 03 to 05 are leaves. They run or they are skipped; either way the
	// run reaches its end and reports what it found.
	newDirs, fuzzing := run.stageFuzzing(profile, targets)
	fuzzing.Log()
	status.noteFailures(fuzzing)

	vulns, vulnScan := run.stageVulns(profile, targets)
	vulnScan.Log()
	status.noteFailures(vulnScan)
	newVulns := run.persistVulns(profile, vulns)

	secrets, secretHunt := run.stageSecrets(profile, targets)
	secretHunt.Log()
	status.noteFailures(secretHunt)
	newSecrets := run.persistSecrets(profile, secrets)
	if newSecrets > 0 {
		notifications.Create(notifications.Credentials, "New credentials found",
			fmt.Sprintf("%s · %d new credential(s) in JavaScript", profile.Domain, newSecrets), "", &p.ID)
	}

	// A scan cancelled mid-run (scratch exhaustion or a restart) must not report
	// completion: the deferred handler records the halt on the profile, so the
	// log and the dashboard status would otherwise disagree.
	if run.ctx.Err() != nil {
		reason := haltReasonFor(run.ctx)
		logf("======================")
		logf("[-] [Target: %s] Run halted before completion: %s", profile.Domain, reason)
		logf("======================\n")
		notifications.Create(notifications.ScanHalted, "Scan halted",
			profile.Domain+" · "+reason, "", &p.ID)
		return
	}

	logf("======================")
	logf("[+] PIPELINE COMPLETE for %s", profile.Domain)
	logf("[+] New Subdomains: %d", newSubdomains)
	logf("[+] New Alive Hosts: %d", newHosts)
	logf("[+] Changed WAF Observations: %d", changedWAFs)
	logf("[+] New Directories: %d", newDirs)
	logf("[+] New Vulnerabilities: %d", newVulns)
	logf("[+] New Secrets Found: %d", newSecrets)
	logf("======================\n")

	newFindings := newSubdomains + newHosts + newVulns + newDirs + newSecrets
	notifications.Create(notifications.ScanFinished, "Scan finished",
		fmt.Sprintf("%s · %d new finding(s)", profile.Domain, newFindings), "", &p.ID)
}

// haltReasonFor maps a cancelled scan context to the short status shown on the
// profile, distinguishing a scratch-storage halt from any other interruption.
func haltReasonFor(ctx context.Context) string {
	if errors.Is(context.Cause(ctx), errScratchLimit) {
		return "scratch storage limit reached"
	}
	return "interrupted"
}

// stageDiscovery enumerates subdomains from every source available to it.
//
// Each source is attempted regardless of what the others did, so a Subfinder
// failure no longer costs you Amass and dnsx. A source that errors after
// emitting results still contributes them.
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

// The persist helpers store a stage's output and notify the dashboard. They are
// always called before the stage's gate is evaluated, so halting never throws
// away what the run already collected.

func (run *runner) persistSubdomains(profile *models.Profile, subdomains []string) int {
	return broadcastIfNew(profile, "subdomains", run.diffSubdomains(&profile.ID, subdomains))
}

func (run *runner) persistHosts(profile *models.Profile, hosts []models.AliveHost) int {
	return broadcastIfNew(profile, "hosts", run.diffHosts(&profile.ID, hosts))
}

func (run *runner) persistWAFs(profile *models.Profile, observations []wafObservation) int {
	return broadcastIfNew(profile, "wafs", run.diffWAFs(&profile.ID, observations))
}

func (run *runner) persistDirectories(profile *models.Profile, dirs []models.DirectoryFinding) int {
	return broadcastIfNew(profile, "directories", run.diffDirectories(&profile.ID, dirs))
}

func (run *runner) persistVulns(profile *models.Profile, vulns []models.Vulnerability) int {
	return broadcastIfNew(profile, "vulnerabilities", run.diffVulns(&profile.ID, vulns))
}

func (run *runner) persistSecrets(profile *models.Profile, secrets []models.SecretFinding) int {
	return broadcastIfNew(profile, "secrets", run.diffSecrets(&profile.ID, secrets))
}

// broadcastIfNew tells the dashboard how many rows of which kind just appeared.
//
// The event used to carry no data, so the only thing a client could do with it was
// refetch and find out — which is why the dashboard re-downloaded the entire profile
// every eight seconds during a scan. With the counts on the event it can show "12 new
// findings, refresh" and leave the page the operator is reading alone.
//
// The Event type already had a data field for this; it was always nil.
func broadcastIfNew(profile *models.Profile, kind string, newCount int) int {
	if newCount > 0 {
		events.Broadcast("discovery_update", profile.ID.String(), map[string]int{kind: newCount})
	}
	return newCount
}

// touchAsset records that correlated reconnaissance data changed for one asset.
//
// LastSeen remains an observation timestamp on the individual tables. LastChanged
// belongs to the subdomain shown in the Nodes table and is deliberately touched only
// after a real diff, never merely because a scanner saw the same value again. A NULL
// host cannot be correlated safely, so it must not update an arbitrary asset.
func touchAsset(profileID *uuid.UUID, host *string) {
	if host == nil {
		return
	}
	database.DB.Model(&models.Subdomain{}).
		Where("profile_id = ? AND host = ?", *profileID, *host).
		UpdateColumn("last_changed", time.Now().UTC())
}

func (run *runner) diffSubdomains(profileID *uuid.UUID, subdomains []string) int {
	newCount := 0
	for _, sub := range subdomains {
		var existing models.Subdomain
		result := database.DB.Where("profile_id = ? AND domain = ?", *profileID, sub).First(&existing)

		if result.Error != nil {
			if run.config.Scan.Verbose {
				logf("[VERBOSE] [+] NEW Subdomain: %s", sub)
			}
			database.DB.Create(&models.Subdomain{
				ProfileID: *profileID,
				Domain:    sub,
			})
			// A newly created subdomain receives LastChanged from autoCreateTime.
			newCount++
		} else {
			if run.config.Scan.Verbose {
				logf("[VERBOSE] [*] Old Subdomain: %s", sub)
			}
			// host is written here as well as by the BeforeSave hook, because hooks do
			// not fire for an Update. This is the second of three mechanisms that keep
			// the correlation key populated — insert hook, this repair on re-sighting,
			// and the one-time backfill — so a row the backfill could not reach is
			// fixed the next time the target is scanned.
			database.DB.Model(&existing).Updates(map[string]interface{}{
				"last_seen": gorm.Expr("CURRENT_TIMESTAMP"),
				"host":      hostkey.NormalizeOrNil(sub),
			})
		}
	}
	return newCount
}

func (run *runner) diffHosts(profileID *uuid.UUID, hosts []models.AliveHost) int {
	newCount := 0
	for _, h := range hosts {
		var existing models.AliveHost
		result := database.DB.Where("profile_id = ? AND url = ?", *profileID, h.URL).First(&existing)

		if result.Error != nil {
			if run.config.Scan.Verbose {
				logf("[VERBOSE] [+] NEW Alive Host: %s (IP: %s | Title: %s)", h.URL, h.IP, h.Title)
			}
			database.DB.Create(&h)
			touchAsset(profileID, hostkey.NormalizeOrNil(h.URL))
			newCount++
		} else {
			if run.config.Scan.Verbose {
				logf("[VERBOSE] [*] Old Alive Host: %s", h.URL)
			}
			// One statement instead of up to three. Every column that can change on a
			// re-sighting goes in the same update, which matters more than it looks:
			// the whole process shares a single database connection, so each extra
			// round trip here is serialised against every in-flight HTTP request.
			changed := existing.IP != h.IP ||
				existing.Title != h.Title ||
				existing.WebServer != h.WebServer ||
				existing.StatusCode != h.StatusCode
			updates := map[string]interface{}{
				"last_seen": gorm.Expr("CURRENT_TIMESTAMP"),
				"host":      hostkey.NormalizeOrNil(h.URL),
			}
			if existing.IP != h.IP {
				updates["ip"] = h.IP
			}
			if existing.Title != h.Title {
				updates["title"] = h.Title
			}
			if existing.WebServer != h.WebServer {
				updates["web_server"] = h.WebServer
			}
			if existing.StatusCode != h.StatusCode {
				updates["status_code"] = h.StatusCode
			}
			database.DB.Model(&existing).Updates(updates)
			if changed {
				touchAsset(profileID, hostkey.NormalizeOrNil(h.URL))
			}
		}
	}
	return newCount
}

func (run *runner) diffWAFs(profileID *uuid.UUID, observations []wafObservation) int {
	changedCount := 0
	for _, observation := range observations {
		var existing models.AliveHost
		if err := database.DB.Where("profile_id = ? AND url = ?", *profileID, observation.URL).
			First(&existing).Error; err != nil {
			logf("[-] Loading HTTP endpoint for WAF observation: %v", err)
			continue
		}
		if existing.WAFName != nil && *existing.WAFName == observation.Name {
			continue
		}
		previous := ""
		if existing.WAFName != nil {
			previous = *existing.WAFName
		}
		if err := database.DB.Model(&existing).UpdateColumn("waf_name", observation.Name).Error; err != nil {
			logf("[-] Storing WAF observation: %v", err)
			continue
		}
		// An initial clean result is useful state, but is not a new finding.
		// A detected product, its replacement, or a previously detected WAF
		// disappearing is a meaningful change to this asset.
		if observation.Name != "none" || (previous != "" && previous != "none") {
			touchAsset(profileID, hostkey.NormalizeOrNil(observation.URL))
			changedCount++
		}
	}
	return changedCount
}

func (run *runner) diffVulns(profileID *uuid.UUID, vulns []models.Vulnerability) int {
	newCount := 0
	for _, v := range vulns {
		var existing models.Vulnerability
		result := database.DB.Where("profile_id = ? AND template_id = ? AND url = ?", *profileID, v.TemplateID, v.URL).First(&existing)

		if result.Error != nil {
			if run.config.Scan.Verbose {
				logf("[VERBOSE] [!] NEW Vulnerability: %s found on %s (%s)", v.TemplateID, v.URL, v.Severity)
			}
			database.DB.Create(&v)
			touchAsset(profileID, hostkey.NormalizeOrNil(v.URL))
			newCount++
		} else {
			if run.config.Scan.Verbose {
				logf("[VERBOSE] [*] Old Vulnerability: %s found on %s", v.TemplateID, v.URL)
			}
			changed := existing.Severity != v.Severity ||
				existing.Name != v.Name || existing.Description != v.Description
			updates := map[string]interface{}{
				"last_seen": gorm.Expr("CURRENT_TIMESTAMP"),
				"host":      hostkey.NormalizeOrNil(v.URL),
			}
			if existing.Severity != v.Severity {
				updates["severity"] = v.Severity
			}
			if existing.Name != v.Name {
				updates["name"] = v.Name
			}
			if existing.Description != v.Description {
				updates["description"] = v.Description
			}
			database.DB.Model(&existing).Updates(updates)
			if changed {
				touchAsset(profileID, hostkey.NormalizeOrNil(v.URL))
			}
		}
	}
	return newCount
}

func (run *runner) diffSecrets(profileID *uuid.UUID, secrets []models.SecretFinding) int {
	newCount := 0
	for _, s := range secrets {
		var existing models.SecretFinding
		result := database.DB.Where("profile_id = ? AND source_url = ? AND secret_type = ? AND secret_value = ?",
			*profileID, s.SourceURL, s.SecretType, s.SecretValue).First(&existing)

		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			// The scanners can label the same value differently. Keep historical
			// evidence on SecretHound's richer row even across separate runs.
			counterpartEngine := "Mantra"
			if s.Engine == "Mantra" {
				counterpartEngine = "SecretHound"
			}
			var counterpart models.SecretFinding
			other := database.DB.Where("profile_id = ? AND source_url = ? AND secret_value = ? AND engine = ?",
				*profileID, s.SourceURL, s.SecretValue, counterpartEngine).First(&counterpart)
			if other.Error == nil {
				if s.Engine == "Mantra" {
					if err := database.DB.Model(&counterpart).Updates(map[string]interface{}{
						"seen_live": counterpart.SeenLive || s.SeenLive, "last_seen": time.Now().UTC(),
					}).Error; err != nil {
						logf("[-] Updating SecretHound evidence: %v", err)
					}
					continue
				}
				s.SeenLive = s.SeenLive || counterpart.SeenLive
			}
			if run.config.Scan.Verbose {
				logf("[VERBOSE] [!] NEW Secret: %s found in %s", s.SecretType, s.SourceURL)
			}
			if err := database.DB.Create(&s).Error; err != nil {
				logf("[-] Storing secret finding: %v", err)
				continue
			}
			touchAsset(profileID, hostkey.NormalizeOrNil(s.SourceURL))
			newCount++
			continue
		}
		if result.Error != nil {
			logf("[-] Loading secret finding: %v", result.Error)
			continue
		}
		if existing.Engine == "SecretHound" && s.Engine == "Mantra" {
			// A Mantra-only rescan cannot replace SecretHound's provenance and
			// richer metadata for the same stored credential.
			if err := database.DB.Model(&existing).Updates(map[string]interface{}{
				"last_seen": time.Now().UTC(), "seen_live": existing.SeenLive || s.SeenLive,
			}).Error; err != nil {
				logf("[-] Updating SecretHound last-seen time: %v", err)
			}
			continue
		}
		if run.config.Scan.Verbose {
			logf("[VERBOSE] [*] Old Secret: %s found in %s", s.SecretType, s.SourceURL)
		}
		changed := existing.Engine != s.Engine || existing.Risk != s.Risk ||
			existing.Description != s.Description || existing.Occurrences != s.Occurrences ||
			!slices.Equal(existing.Context, s.Context) ||
			(existing.ArchiveURL == "" && s.ArchiveURL != "") || (!existing.SeenLive && s.SeenLive)
		if existing.ArchiveURL == "" {
			existing.ArchiveURL = s.ArchiveURL
		}
		existing.SeenLive = existing.SeenLive || s.SeenLive
		existing.Engine = s.Engine
		existing.Risk = s.Risk
		existing.Description = s.Description
		existing.Context = s.Context
		existing.Occurrences = s.Occurrences
		if err := database.DB.Save(&existing).Error; err != nil {
			logf("[-] Updating secret finding: %v", err)
			continue
		}
		if changed {
			touchAsset(profileID, hostkey.NormalizeOrNil(s.SourceURL))
		}
	}
	return newCount
}

func (run *runner) diffDirectories(profileID *uuid.UUID, dirs []models.DirectoryFinding) int {
	newCount := 0
	for _, d := range dirs {
		var existing models.DirectoryFinding
		result := database.DB.Where("profile_id = ? AND dir_url = ?", *profileID, d.DirURL).First(&existing)

		if result.Error != nil {
			if run.config.Scan.Verbose {
				logf("[VERBOSE] [+] NEW Directory: %s (%d)", d.DirURL, d.StatusCode)
			}
			database.DB.Create(&d)
			touchAsset(profileID, hostkey.NormalizeOrNil(d.SubdomainURL))
			newCount++
		} else {
			if run.config.Scan.Verbose {
				logf("[VERBOSE] [*] Old Directory: %s", d.DirURL)
			}
			changed := existing.StatusCode != d.StatusCode
			updates := map[string]interface{}{
				"last_seen": gorm.Expr("CURRENT_TIMESTAMP"),
				"host":      hostkey.NormalizeOrNil(d.SubdomainURL),
			}
			if existing.StatusCode != d.StatusCode {
				updates["status_code"] = d.StatusCode
			}
			database.DB.Model(&existing).Updates(updates)
			if changed {
				touchAsset(profileID, hostkey.NormalizeOrNil(d.SubdomainURL))
			}
		}
	}
	return newCount
}
