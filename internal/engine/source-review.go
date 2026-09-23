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
	"strings"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type GauResult struct {
	Url string `json:"url"`
}

type KatanaResult struct {
	Request struct {
		Endpoint string `json:"endpoint"`
	} `json:"request"`
}

type MantraResult struct {
	Type   string `json:"type"`
	Secret string `json:"secret"`
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

	jsURLs := collectJSSources(profile, targets)
	report := newStageReport("Stage 05 Secret Hunting", profile.Domain)

	if len(jsURLs) == 0 {
		report.skip("mantra", "no JS URLs were discovered")
		report.skip("secrethound", "no JS URLs were discovered")
		return nil, report
	}

	log.Printf("[*] [Target: %s] Feeding %d JS URL(s) into the secret scanners...", profile.Domain, len(jsURLs))

	houndSecrets, err := scanWithSecretHound(profile, jsURLs)
	report.record("secrethound", len(houndSecrets), err)

	mantraSecrets, err := scanWithMantra(profile, jsURLs)
	report.record("mantra", len(mantraSecrets), err)
	secrets := mergeSecrets(houndSecrets, mantraSecrets)

	report.Unique = len(secrets)
	return secrets, report
}

// collectJSSources gathers candidate JavaScript URLs from every source it can and
// returns the merged, de-duplicated set. It logs its own report.
func collectJSSources(profile *models.Profile, targets []models.AliveHost) []string {
	report := newStageReport("Stage 05 JS Source Collection", profile.Domain)

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

	// gau only needs the domain name, so it runs even when nothing is alive.
	historical, err := collectGau(profile)
	report.record("gau", len(historical), err)

	// Historical URLs come from archives and are mostly dead, so they are the one
	// source worth validating before use.
	if len(historical) > 0 {
		alive, err := validateJSURLs(profile, historical)
		report.record("httpx[js-validation]", len(alive), err)
		add(alive)
	} else {
		report.skip("httpx[js-validation]", "gau returned no historical JS URLs")
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

	report.Unique = len(jsURLs)
	report.Log()

	return jsURLs
}

// collectGau pulls historical URLs for the domain and keeps the JS-looking ones.
func collectGau(profile *models.Profile) ([]string, error) {
	log.Printf("[*] [Target: %s] Running gau...", profile.Domain)

	outb, err := runTool("gau", []string{"--json", "--subs", profile.Domain}, nil, timeoutGau)

	var urls []string
	scanner := newLineScanner(outb)
	for scanner.Scan() {
		var res GauResult
		if jsonErr := json.Unmarshal(scanner.Bytes(), &res); jsonErr != nil {
			continue
		}
		if isJSFile(res.Url) {
			urls = append(urls, res.Url)
		}
	}

	return urls, err
}

// validateJSURLs keeps only the URLs that currently answer with a 200.
func validateJSURLs(profile *models.Profile, urls []string) ([]string, error) {
	log.Printf("[*] [Target: %s] Validating %d historical JS URL(s) via httpx...", profile.Domain, len(urls))

	stdin := strings.NewReader(strings.Join(urls, "\n"))
	outb, err := runTool("httpx", []string{"-silent", "-mc", "200"}, stdin, timeoutHttpx)

	return parsePlainURLs(outb), err
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

	stdin := strings.NewReader(strings.Join(jsURLs, "\n"))
	outb, err := runTool("mantra", []string{"-j"}, stdin, timeoutMantra)

	var secrets []models.SecretFinding
	scanner := newLineScanner(outb)
	for scanner.Scan() {
		var res MantraResult
		if jsonErr := json.Unmarshal(scanner.Bytes(), &res); jsonErr != nil {
			continue
		}
		if strings.TrimSpace(res.Type) == "" || strings.TrimSpace(res.Secret) == "" {
			continue
		}
		secrets = append(secrets, models.SecretFinding{
			ProfileID:   profile.ID,
			SecretType:  res.Type,
			SecretValue: res.Secret,
			SourceURL:   "mantra-discovery",
			Engine:      "Mantra",
		})
	}

	return secrets, err
}

// SecretHound recognizes .urls as a URL list even when it contains one entry.
// Its JSON output is written on close, so read the file after the process exits.
func scanWithSecretHound(profile *models.Profile, jsURLs []string) ([]models.SecretFinding, error) {
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
	if len(urls) == 0 {
		return nil, fmt.Errorf("no valid HTTP(S) JS URLs for SecretHound")
	}

	dir, err := os.MkdirTemp("", "icevirtue-secrethound-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	inputPath := filepath.Join(dir, "targets.urls")
	outputPath := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(inputPath, []byte(strings.Join(urls, "\n")+"\n"), 0600); err != nil {
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
		if strings.TrimSpace(result.Type) == "" || strings.TrimSpace(result.Value) == "" ||
			!validHTTPURL(result.SourceURL) || !allowed[result.SourceURL] || result.Occurrences < 0 {
			invalid++
			continue
		}
		findings = append(findings, models.SecretFinding{
			ProfileID: profile.ID, SourceURL: result.SourceURL,
			SecretType: result.Type, SecretValue: result.Value,
			Engine: "SecretHound", Risk: result.Risk,
			Description: result.Description, Context: result.Context,
			Occurrences: result.Occurrences,
		})
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

// Retain each SecretHound source; its sourced result takes precedence over an
// unattributed Mantra result with the same type and value.
func mergeSecrets(hound, mantra []models.SecretFinding) []models.SecretFinding {
	type credential struct{ kind, value string }
	type sourceFinding struct{ source, kind, value string }
	sourced := make(map[credential]bool)
	seen := make(map[sourceFinding]bool)
	merged := make([]models.SecretFinding, 0, len(hound)+len(mantra))
	for _, s := range hound {
		key := sourceFinding{s.SourceURL, s.SecretType, s.SecretValue}
		if seen[key] {
			continue
		}
		seen[key] = true
		sourced[credential{s.SecretType, s.SecretValue}] = true
		merged = append(merged, s)
	}
	for _, s := range mantra {
		if sourced[credential{s.SecretType, s.SecretValue}] {
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
