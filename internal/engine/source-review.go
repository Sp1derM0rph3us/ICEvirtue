package engine

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
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
		report.skip("mantra", "no live JS files were discovered")
		report.skip("secretfinder.py", "no live JS files were discovered")
		return nil, report
	}

	log.Printf("[*] [Target: %s] Feeding %d live JS file(s) into the secret scanners...", profile.Domain, len(jsURLs))

	var secrets []models.SecretFinding
	seen := make(map[string]bool)

	mantraSecrets, err := scanWithMantra(profile, jsURLs)
	report.record("mantra", len(mantraSecrets), err)
	secrets = mergeSecrets(secrets, mantraSecrets, seen)

	sfSecrets, err := scanWithSecretFinder(profile, jsURLs)
	report.record("secretfinder.py", len(sfSecrets), err)
	secrets = mergeSecrets(secrets, sfSecrets, seen)

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
		if res.Type == "" && res.Secret == "" {
			continue
		}
		secrets = append(secrets, models.SecretFinding{
			ProfileID:   profile.ID,
			SecretType:  res.Type,
			SecretValue: res.Secret,
			SourceURL:   "mantra-discovery",
		})
	}

	return secrets, err
}

// scanWithSecretFinder runs SecretFinder over a temp file listing the JS URLs,
// since it takes its input from a file rather than stdin.
func scanWithSecretFinder(profile *models.Profile, jsURLs []string) ([]models.SecretFinding, error) {
	log.Printf("[*] [Target: %s] Running secretfinder.py...", profile.Domain)

	tmpFile, err := os.CreateTemp("", "js_targets*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(strings.Join(jsURLs, "\n")); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	outb, runErr := runTool("secretfinder.py", []string{"-i", tmpFile.Name()}, nil, timeoutSecretFinder)

	var secrets []models.SecretFinding
	var currentURL string

	scanner := newLineScanner(outb)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "URL:") {
			currentURL = strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
			continue
		}

		if !strings.HasPrefix(line, "->") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		secrets = append(secrets, models.SecretFinding{
			ProfileID:   profile.ID,
			SecretType:  strings.TrimSpace(strings.TrimPrefix(parts[0], "->")),
			SecretValue: strings.TrimSpace(parts[1]),
			SourceURL:   currentURL,
		})
	}

	return secrets, runErr
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

// mergeSecrets appends the secrets not already present, keyed on type and value
// so the same credential found by both scanners is stored once.
func mergeSecrets(into, from []models.SecretFinding, seen map[string]bool) []models.SecretFinding {
	for _, s := range from {
		sig := s.SecretType + "|" + s.SecretValue
		if seen[sig] {
			continue
		}
		seen[sig] = true
		into = append(into, s)
	}
	return into
}
