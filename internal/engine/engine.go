package engine

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

var Verbose bool

var DnsxList string

var DirectoryList string

var SkipAmass bool

var SkipNuclei bool

// WideTargets widens which alive hosts reach stages 03 to 05. See targetHosts.
var WideTargets bool

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
func OrchestrateScan(profile *models.Profile) {
	var p models.Profile
	if err := database.DB.First(&p, profile.ID).Error; err != nil {
		log.Printf("[-] Profile %s not found in DB before scan", profile.ID)
		return
	}

	if p.IsScanning {
		log.Printf("[-] Skipping scan for %s. A scan is already currently running.", p.Domain)
		return
	}

	// Work from the freshly loaded row for the rest of the pipeline. The caller's
	// copy is captured when the scan is triggered and goes stale if the profile's
	// Domain or Mode is edited before the scan actually starts.
	profile = &p

	database.DB.Model(&p).Update("is_scanning", true)
	events.Broadcast("profile_update", p.ID.String(), nil)

	status := &runStatus{}
	defer func() {
		database.DB.Model(&p).Updates(map[string]interface{}{
			"is_scanning":      false,
			"last_scan":        time.Now(),
			"last_scan_status": status.summary(),
		})
		events.Broadcast("profile_update", p.ID.String(), nil)
	}()

	log.Printf("======================")
	log.Printf("[+] INITIATING SCAN PIPELINE for Profile: %s", profile.Domain)
	log.Printf("======================")

	// Stage 01. Halting here means no source produced anything, so there is no
	// attack surface to enumerate and the target itself is suspect.
	subdomains, discovery := stageDiscovery(profile)
	discovery.Log()
	status.noteFailures(discovery)
	newSubdomains := persistSubdomains(profile, subdomains)

	if len(subdomains) == 0 {
		status.halt("no subdomains found from any source")
		log.Printf("[-] [Target: %s] Halting run: every discovery source failed or came back empty. Check the target domain is spelled correctly.", profile.Domain)
		return
	}

	// Stage 02. Halting here means nothing answered, so no later stage has a
	// host to work with. The subdomains above are already saved.
	hosts, validation := stageValidation(profile, subdomains)
	validation.Log()
	status.noteFailures(validation)
	newHosts := persistHosts(profile, hosts)

	if len(hosts) == 0 {
		status.halt("no host answered HTTP")
		log.Printf("[-] [Target: %s] Halting run: none of the %d discovered subdomains answered HTTP, so nothing downstream can execute.", profile.Domain, len(subdomains))
		log.Printf("[+] [Target: %s] Persisted %d subdomain(s), %d new.", profile.Domain, len(subdomains), newSubdomains)
		return
	}

	targets := targetHosts(profile, hosts)

	// Stages 03 to 05 are leaves. They run or they are skipped; either way the
	// run reaches its end and reports what it found.
	dirs, fuzzing := stageFuzzing(profile, targets)
	fuzzing.Log()
	status.noteFailures(fuzzing)
	newDirs := persistDirectories(profile, dirs)

	vulns, vulnScan := stageVulns(profile, targets)
	vulnScan.Log()
	status.noteFailures(vulnScan)
	newVulns := persistVulns(profile, vulns)

	secrets, secretHunt := stageSecrets(profile, targets)
	secretHunt.Log()
	status.noteFailures(secretHunt)
	newSecrets := persistSecrets(profile, secrets)

	log.Printf("======================")
	log.Printf("[+] PIPELINE COMPLETE for %s", profile.Domain)
	log.Printf("[+] New Subdomains: %d", newSubdomains)
	log.Printf("[+] New Alive Hosts: %d", newHosts)
	log.Printf("[+] New Directories: %d", newDirs)
	log.Printf("[+] New Vulnerabilities: %d", newVulns)
	log.Printf("[+] New Secrets Found: %d", newSecrets)
	log.Printf("======================\n")
}

// stageDiscovery enumerates subdomains from every source available to it.
//
// Each source is attempted regardless of what the others did, so a Subfinder
// failure no longer costs you Amass and dnsx. A source that errors after
// emitting results still contributes them.
func stageDiscovery(profile *models.Profile) ([]string, *stageReport) {
	report := newStageReport("Stage 01 Discovery", profile.Domain)

	unique := make(map[string]bool)
	var subdomains []string

	add := func(found []string) {
		for _, sub := range found {
			if sub != "" && !unique[sub] {
				unique[sub] = true
				subdomains = append(subdomains, sub)
			}
		}
	}

	subs, err := RunSubfinder(profile)
	add(subs)
	report.record("subfinder", len(subs), err)

	if profile.Mode != "full" {
		report.skip("amass", "profile is not in full mode")
		report.skip("dnsx", "profile is not in full mode")

		report.Unique = len(subdomains)
		return subdomains, report
	}

	if SkipAmass {
		report.skip("amass", "--skip-amass was passed")
	} else {
		amassSubs, err := RunAmass(profile)
		add(amassSubs)
		report.record("amass", len(amassSubs), err)
	}

	wordlists := splitList(DnsxList)
	if len(wordlists) == 0 {
		report.skip("dnsx", "no --dnsx-list was provided")
	} else {
		for _, wlPath := range wordlists {
			dnsxSubs, err := RunDnsx(profile, wlPath)
			add(dnsxSubs)
			report.record(fmt.Sprintf("dnsx[%s]", filepath.Base(wlPath)), len(dnsxSubs), err)
		}
	}

	report.Unique = len(subdomains)
	return subdomains, report
}

// stageValidation probes the discovered names and keeps the ones that answered.
// A partial httpx run still counts: whatever it confirmed alive is used.
func stageValidation(profile *models.Profile, subdomains []string) ([]models.AliveHost, *stageReport) {
	report := newStageReport("Stage 02 Validation", profile.Domain)

	hosts, err := RunHttpx(profile, subdomains)
	report.record("httpx", len(hosts), err)

	report.Unique = len(hosts)
	return hosts, report
}

// stageFuzzing walks the probe-worthy hosts with the built-in fuzzer.
func stageFuzzing(profile *models.Profile, targets []models.AliveHost) ([]models.DirectoryFinding, *stageReport) {
	report := newStageReport("Stage 03 Directory Fuzzing", profile.Domain)

	wordlists := splitList(DirectoryList)

	switch {
	case len(wordlists) == 0:
		report.skip("fuzzer", "no --directory-list was provided")
		return nil, report
	case len(targets) == 0:
		report.skip("fuzzer", "no probe-worthy hosts to fuzz")
		return nil, report
	}

	dirs, err := RunDirectoryFuzzing(profile, targets, wordlists)
	report.record("fuzzer", len(dirs), err)

	report.Unique = len(dirs)
	return dirs, report
}

// stageVulns scans the probe-worthy hosts with nuclei.
func stageVulns(profile *models.Profile, targets []models.AliveHost) ([]models.Vulnerability, *stageReport) {
	report := newStageReport("Stage 04 Vulnerability Scanning", profile.Domain)

	switch {
	case SkipNuclei:
		report.skip("nuclei", "--skip-nuclei was passed")
		return nil, report
	case len(targets) == 0:
		report.skip("nuclei", "no probe-worthy hosts to scan")
		return nil, report
	}

	vulns, err := RunNuclei(profile, targets)
	report.record("nuclei", len(vulns), err)

	report.Unique = len(vulns)
	return vulns, report
}

// targetHosts decides which alive hosts are worth handing to stages 03 to 05.
//
// By default only hosts answering 200, 301, 302 or 307 qualify, which is the
// historical behaviour. With --wide-targets everything httpx reported qualifies
// except a plain 404, on the grounds that a 403 or a 500 on / tells you nothing
// about what /admin returns, and finding exactly that is the point of fuzzing.
func targetHosts(profile *models.Profile, hosts []models.AliveHost) []models.AliveHost {
	var targets []models.AliveHost

	for _, h := range hosts {
		if WideTargets {
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
	if WideTargets {
		policy = "wide (any status except 404)"
	}
	log.Printf("[*] [Target: %s] Target filter %s selected %d of %d alive host(s)",
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

func persistSubdomains(profile *models.Profile, subdomains []string) int {
	return broadcastIfNew(profile, diffSubdomains(&profile.ID, subdomains))
}

func persistHosts(profile *models.Profile, hosts []models.AliveHost) int {
	return broadcastIfNew(profile, diffHosts(&profile.ID, hosts))
}

func persistDirectories(profile *models.Profile, dirs []models.DirectoryFinding) int {
	return broadcastIfNew(profile, diffDirectories(&profile.ID, dirs))
}

func persistVulns(profile *models.Profile, vulns []models.Vulnerability) int {
	return broadcastIfNew(profile, diffVulns(&profile.ID, vulns))
}

func persistSecrets(profile *models.Profile, secrets []models.SecretFinding) int {
	return broadcastIfNew(profile, diffSecrets(&profile.ID, secrets))
}

func broadcastIfNew(profile *models.Profile, newCount int) int {
	if newCount > 0 {
		events.Broadcast("discovery_update", profile.ID.String(), nil)
	}
	return newCount
}

func diffSubdomains(profileID *uuid.UUID, subdomains []string) int {
	newCount := 0
	for _, sub := range subdomains {
		var existing models.Subdomain
		result := database.DB.Where("profile_id = ? AND domain = ?", *profileID, sub).First(&existing)

		if result.Error != nil {
			if Verbose {
				log.Printf("[VERBOSE] [+] NEW Subdomain: %s", sub)
			}
			database.DB.Create(&models.Subdomain{
				ProfileID: *profileID,
				Domain:    sub,
			})
			newCount++
		} else {
			if Verbose {
				log.Printf("[VERBOSE] [*] Old Subdomain: %s", sub)
			}
			database.DB.Model(&existing).Update("LastSeen", gorm.Expr("CURRENT_TIMESTAMP"))
		}
	}
	return newCount
}

func diffHosts(profileID *uuid.UUID, hosts []models.AliveHost) int {
	newCount := 0
	for _, h := range hosts {
		var existing models.AliveHost
		result := database.DB.Where("profile_id = ? AND url = ?", *profileID, h.URL).First(&existing)

		if result.Error != nil {
			if Verbose {
				log.Printf("[VERBOSE] [+] NEW Alive Host: %s (IP: %s | Title: %s)", h.URL, h.IP, h.Title)
			}
			database.DB.Create(&h)
			newCount++
		} else {
			if Verbose {
				log.Printf("[VERBOSE] [*] Old Alive Host: %s", h.URL)
			}
			database.DB.Model(&existing).Update("LastSeen", gorm.Expr("CURRENT_TIMESTAMP"))

			if h.IP != "" && existing.IP != h.IP {
				database.DB.Model(&existing).Update("IP", h.IP)
			}
			if h.StatusCode != 0 && existing.StatusCode != h.StatusCode {
				database.DB.Model(&existing).Update("StatusCode", h.StatusCode)
			}
		}
	}
	return newCount
}

func diffVulns(profileID *uuid.UUID, vulns []models.Vulnerability) int {
	newCount := 0
	for _, v := range vulns {
		var existing models.Vulnerability
		result := database.DB.Where("profile_id = ? AND template_id = ? AND url = ?", *profileID, v.TemplateID, v.URL).First(&existing)

		if result.Error != nil {
			if Verbose {
				log.Printf("[VERBOSE] [!] NEW Vulnerability: %s found on %s (%s)", v.TemplateID, v.URL, v.Severity)
			}
			database.DB.Create(&v)
			newCount++
		} else {
			if Verbose {
				log.Printf("[VERBOSE] [*] Old Vulnerability: %s found on %s", v.TemplateID, v.URL)
			}
			database.DB.Model(&existing).Update("LastSeen", gorm.Expr("CURRENT_TIMESTAMP"))
		}
	}
	return newCount
}

func diffSecrets(profileID *uuid.UUID, secrets []models.SecretFinding) int {
	newCount := 0
	for _, s := range secrets {
		var existing models.SecretFinding
		result := database.DB.Where("profile_id = ? AND secret_type = ? AND secret_value = ?", *profileID, s.SecretType, s.SecretValue).First(&existing)

		if result.Error != nil {
			if Verbose {
				log.Printf("[VERBOSE] [!] NEW Secret: %s found in %s", s.SecretType, s.SourceURL)
			}
			database.DB.Create(&s)
			newCount++
		} else {
			if Verbose {
				log.Printf("[VERBOSE] [*] Old Secret: %s found in %s", s.SecretType, s.SourceURL)
			}
			database.DB.Model(&existing).Update("LastSeen", gorm.Expr("CURRENT_TIMESTAMP"))
		}
	}
	return newCount
}

func diffDirectories(profileID *uuid.UUID, dirs []models.DirectoryFinding) int {
	newCount := 0
	for _, d := range dirs {
		var existing models.DirectoryFinding
		result := database.DB.Where("profile_id = ? AND dir_url = ?", *profileID, d.DirURL).First(&existing)

		if result.Error != nil {
			if Verbose {
				log.Printf("[VERBOSE] [+] NEW Directory: %s (%d)", d.DirURL, d.StatusCode)
			}
			database.DB.Create(&d)
			newCount++
		} else {
			if Verbose {
				log.Printf("[VERBOSE] [*] Old Directory: %s", d.DirURL)
			}
			database.DB.Model(&existing).Update("LastSeen", gorm.Expr("CURRENT_TIMESTAMP"))
			if existing.StatusCode != d.StatusCode {
				database.DB.Model(&existing).Update("StatusCode", d.StatusCode)
			}
		}
	}
	return newCount
}
