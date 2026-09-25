package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type KatanaResult struct {
	Request struct {
		Endpoint string `json:"endpoint"`
	} `json:"request"`
}

type SecretHoundResult struct {
	Type        string   `json:"type"`
	Risk        string   `json:"risk"`
	Value       string   `json:"value"`
	SourceURL   string   `json:"source_url"`
	Context     []string `json:"context"`
	Occurrences int      `json:"occurrences"`
	Description string   `json:"description"`
}

var jsExtensions = []string{".js", ".json", ".ts", ".tsx"}

func isJSFile(url string) bool {
	for _, ext := range jsExtensions {
		if strings.Contains(url, ext) {
			return true
		}
	}
	return false
}

// stageSecrets hunts hard-coded secrets in JavaScript, in two sub-phases.
//
// Collection gathers candidate JS URLs from several independent sources and is
// logged as its own report, because those tools contribute URLs rather than
// findings. Scanning then feeds the merged set to the secret scanners. No tool
// failure in either sub-phase stops the other tools, and the stage never halts
// the run: nothing downstream consumes its output.
func stageSecrets(profile *models.Profile, targets []models.AliveHost) ([]models.SecretFinding, *stageReport) {
	log.Printf("[*] [Target: %s] Stage 05 Secret Hunting starting...", profile.Domain)

	sources := collectJSSources(profile, targets)
	defer sources.cleanup()
	report := newStageReport("Stage 05 Secret Hunting", profile.Domain)

	if len(sources.live) == 0 && len(sources.archived) == 0 {
		report.skip("mantra", "no live JS URLs were discovered")
		report.skip("secrethound", "no live or archived JS files were discovered")
		return nil, report
	}

	log.Printf("[*] [Target: %s] Scanning %d live URL(s) and %d archived body/bodies...", profile.Domain, len(sources.live), len(sources.archived))

	houndSecrets, err := scanWithSecretHoundSources(profile, sources.live, sources.archived)
	report.record("secrethound", len(houndSecrets), err)

	var mantraSecrets []models.SecretFinding
	if len(sources.live) > 0 {
		mantraSecrets, err = scanWithMantra(profile, sources.live)
		report.record("mantra", len(mantraSecrets), err)
	} else {
		report.skip("mantra", "no live JS URLs were discovered")
	}
	secrets := mergeSecrets(houndSecrets, mantraSecrets)

	report.Unique = len(secrets)
	return secrets, report
}

// collectJSSources gathers candidate JavaScript URLs from every source it can and
// returns the merged, de-duplicated set. It logs its own report.
func collectJSSources(profile *models.Profile, targets []models.AliveHost) jsSources {
	report := newStageReport("Stage 05 JS Source Collection", profile.Domain)
	sources := jsSources{archived: make(map[string][]archiveEvidence)}

	unique := make(map[string]bool)
	var jsURLs []string

	add := func(urls []string) {
		for _, u := range urls {
			if u != "" && !unique[u] {
				unique[u] = true
				jsURLs = append(jsURLs, u)
			}
		}
	}

	// Waymore also runs when no live hosts were found.
	historical, archived, cleanup, err := collectWaymore(profile)
	sources.archived, sources.cleanup = archived, cleanup
	report.record("waymore", len(historical)+len(archived), err)

	// Historical URLs come from archives and are mostly dead, so they are the one
	// source worth validating before use.
	if len(historical) > 0 {
		alive, err := validateJSURLs(profile, historical)
		report.record("httpx[js-validation]", len(alive), err)
		add(alive)
	} else {
		report.skip("httpx[js-validation]", "waymore returned no historical JS URLs")
	}

	var hostURLs []string
	for _, h := range targets {
		hostURLs = append(hostURLs, h.URL)
	}

	if len(hostURLs) > 0 {
		crawled, err := collectKatana(profile, hostURLs)
		add(crawled)
		report.record("katana", len(crawled), err)

		scripts, err := collectSubjs(profile, hostURLs)
		add(scripts)
		report.record("subjs", len(scripts), err)
	} else {
		report.skip("katana", "no probe-worthy hosts to crawl")
		report.skip("subjs", "no probe-worthy hosts to scrape")
	}

	report.Unique = len(jsURLs) + len(archived)
	report.Log()

	sources.live = jsURLs
	return sources
}

// validateJSURLs keeps only the URLs that currently answer with a 200.
func validateJSURLs(profile *models.Profile, urls []string) ([]string, error) {
	log.Printf("[*] [Target: %s] Validating %d historical JS URL(s) via httpx...", profile.Domain, len(urls))

	stdin := strings.NewReader(strings.Join(urls, "\n"))
	outb, err := runTool("httpx", []string{"-silent", "-mc", "200"}, stdin, timeoutHttpx)

	allowed := make(map[string]bool, len(urls))
	for _, candidate := range urls {
		allowed[candidate] = true
	}
	var live []string
	for _, candidate := range parsePlainURLs(outb) {
		if allowed[candidate] {
			live = append(live, candidate)
		}
	}
	return live, err
}

// collectKatana crawls the live hosts and keeps the JS endpoints it finds.
func collectKatana(profile *models.Profile, hostURLs []string) ([]string, error) {
	log.Printf("[*] [Target: %s] Running katana against %d host(s)...", profile.Domain, len(hostURLs))

	stdin := strings.NewReader(strings.Join(hostURLs, "\n"))
	outb, err := runTool("katana", []string{"-silent", "-j", "-d", "2"}, stdin, timeoutKatana)

	var urls []string
	scanner := newLineScanner(outb)
	for scanner.Scan() {
		var res KatanaResult
		if jsonErr := json.Unmarshal(scanner.Bytes(), &res); jsonErr != nil {
			continue
		}
		if url := res.Request.Endpoint; url != "" && isJSFile(url) {
			urls = append(urls, url)
		}
	}

	return urls, err
}

// collectSubjs scrapes script references straight out of the live hosts.
func collectSubjs(profile *models.Profile, hostURLs []string) ([]string, error) {
	log.Printf("[*] [Target: %s] Running subjs...", profile.Domain)

	stdin := strings.NewReader(strings.Join(hostURLs, "\n"))
	outb, err := runTool("subjs", nil, stdin, timeoutSubjs)

	return parsePlainURLs(outb), err
}

// scanWithMantra looks for secrets in the given JS files.
func scanWithMantra(profile *models.Profile, jsURLs []string) ([]models.SecretFinding, error) {
	log.Printf("[*] [Target: %s] Running mantra...", profile.Domain)

	urls := make([]string, 0, len(jsURLs))
	allowed := make(map[string]bool, len(jsURLs))
	for _, raw := range jsURLs {
		u := strings.TrimSpace(raw)
		if validHTTPURL(u) && !allowed[u] {
			allowed[u] = true
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("no valid HTTP(S) JS URLs for Mantra")
	}

	stdin := strings.NewReader(strings.Join(urls, "\n") + "\n")
	// -s suppresses the banner. Mantra has no JSON flag; findings are text lines.
	outb, runErr := runTool("mantra", []string{"-s"}, stdin, timeoutMantra)

	var secrets []models.SecretFinding
	var malformed, requestErrors int
	scanner := newLineScanner(outb)
	for scanner.Scan() {
		line := strings.TrimSpace(ansiPattern.ReplaceAllString(scanner.Text(), ""))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[-]") {
			requestErrors++
			continue
		}
		if !strings.HasPrefix(line, "[+] ") {
			malformed++
			continue
		}
		source, bracketed, ok := strings.Cut(strings.TrimPrefix(line, "[+] "), " [")
		if !ok || !strings.HasSuffix(bracketed, "]") || !validHTTPURL(source) || !allowed[source] {
			malformed++
			continue
		}
		value := strings.TrimSpace(strings.TrimSuffix(bracketed, "]"))
		if value == "" {
			malformed++
			continue
		}
		secrets = append(secrets, models.SecretFinding{
			ProfileID:   profile.ID,
			SecretType:  "generic",
			SecretValue: value,
			SourceURL:   source,
			Engine:      "Mantra",
			SeenLive:    true,
		})
	}

	if malformed > 0 {
		runErr = errors.Join(runErr, fmt.Errorf("Mantra returned %d malformed output line(s)", malformed))
	}
	if requestErrors > 0 {
		runErr = errors.Join(runErr, fmt.Errorf("Mantra reported %d request error(s)", requestErrors))
	}
	if err := scanner.Err(); err != nil {
		runErr = errors.Join(runErr, fmt.Errorf("reading Mantra output: %w", err))
	}
	return secrets, runErr
}

// SecretHound recognizes .urls as a URL list even when it contains one entry.
// Its JSON output is written on close, so read the file after the process exits.
func scanWithSecretHound(profile *models.Profile, jsURLs []string) ([]models.SecretFinding, error) {
	return scanWithSecretHoundSources(profile, jsURLs, nil)
}

func scanWithSecretHoundSources(profile *models.Profile, jsURLs []string, archived map[string][]archiveEvidence) ([]models.SecretFinding, error) {
	log.Printf("[*] [Target: %s] Running secrethound...", profile.Domain)

	urls := make([]string, 0, len(jsURLs))
	allowed := make(map[string]bool, len(jsURLs))
	for _, raw := range jsURLs {
		u := strings.TrimSpace(raw)
		if validHTTPURL(u) && !allowed[u] {
			allowed[u] = true
			urls = append(urls, u)
		}
	}
	paths := make([]string, 0, len(archived))
	for path := range archived {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	if len(urls) == 0 && len(paths) == 0 {
		return nil, fmt.Errorf("no valid HTTP(S) JS URLs or archived files for SecretHound")
	}

	dir, err := os.MkdirTemp("", "icevirtue-secrethound-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	inputPath := filepath.Join(dir, "targets.urls")
	outputPath := filepath.Join(dir, "findings.json")
	inputs := append(urls, paths...)
	if err := os.WriteFile(inputPath, []byte(strings.Join(inputs, "\n")+"\n"), 0600); err != nil {
		return nil, err
	}

	_, runErr := runTool("secrethound", []string{"-i", inputPath, "-o", outputPath, "--silent", "--no-progress"}, nil, timeoutSecretHound)
	data, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		return nil, errors.Join(runErr, fmt.Errorf("reading SecretHound JSON: %w", readErr))
	}
	var results []SecretHoundResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, errors.Join(runErr, fmt.Errorf("parsing SecretHound JSON: %w", err))
	}

	findings := make([]models.SecretFinding, 0, len(results))
	invalid := 0
	for _, result := range results {
		if strings.TrimSpace(result.Type) == "" || strings.TrimSpace(result.Value) == "" || result.Occurrences < 0 {
			invalid++
			continue
		}
		base := models.SecretFinding{ProfileID: profile.ID, SecretType: result.Type,
			SecretValue: result.Value, Engine: "SecretHound", Risk: result.Risk,
			Description: result.Description, Context: result.Context, Occurrences: result.Occurrences}
		if allowed[result.SourceURL] {
			base.SourceURL, base.SeenLive = result.SourceURL, true
			findings = append(findings, base)
			continue
		}
		local, err := url.Parse(result.SourceURL)
		if err != nil || local.Scheme != "file" || local.Host != "" {
			invalid++
			continue
		}
		refs := archived[local.Path]
		if len(refs) == 0 {
			invalid++
			continue
		}
		for _, ref := range refs {
			finding := base
			finding.SourceURL, finding.ArchiveURL = ref.OriginalURL, ref.ArchiveURL
			findings = append(findings, finding)
		}
	}
	if invalid > 0 {
		runErr = errors.Join(runErr, fmt.Errorf("SecretHound returned %d malformed finding(s)", invalid))
	}
	return findings, runErr
}

func validHTTPURL(raw string) bool {
	if raw == "" || strings.ContainsAny(raw, "\r\n\t") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}

// parsePlainURLs reads one URL per line, which is what httpx -silent and subjs emit.
func parsePlainURLs(out *bytes.Buffer) []string {
	if out == nil {
		return nil
	}

	var urls []string
	scanner := newLineScanner(out)
	for scanner.Scan() {
		if url := strings.TrimSpace(scanner.Text()); url != "" {
			urls = append(urls, url)
		}
	}

	return urls
}

// Retain each SecretHound source; its result takes precedence over a Mantra
// result with the same source and value, even when their types differ.
func mergeSecrets(hound, mantra []models.SecretFinding) []models.SecretFinding {
	type credential struct{ source, value string }
	type sourceFinding struct{ source, kind, value string }
	sourced := make(map[credential]bool)
	seen := make(map[sourceFinding]bool)
	merged := make([]models.SecretFinding, 0, len(hound)+len(mantra))
	for _, s := range hound {
		key := sourceFinding{s.SourceURL, s.SecretType, s.SecretValue}
		if seen[key] {
			for i := range merged {
				if merged[i].SourceURL == s.SourceURL && merged[i].SecretType == s.SecretType && merged[i].SecretValue == s.SecretValue {
					merged[i].SeenLive = merged[i].SeenLive || s.SeenLive
					if merged[i].ArchiveURL == "" {
						merged[i].ArchiveURL = s.ArchiveURL
					}
					break
				}
			}
			continue
		}
		seen[key] = true
		sourced[credential{s.SourceURL, s.SecretValue}] = true
		merged = append(merged, s)
	}
	for _, s := range mantra {
		if sourced[credential{s.SourceURL, s.SecretValue}] {
			for i := range merged {
				if merged[i].SourceURL == s.SourceURL && merged[i].SecretValue == s.SecretValue {
					merged[i].SeenLive = true
				}
			}
			continue
		}
		key := sourceFinding{s.SourceURL, s.SecretType, s.SecretValue}
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, s)
	}
	return merged
}
