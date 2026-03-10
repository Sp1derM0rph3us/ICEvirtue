package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"os"
	"os/exec"
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

func RunSourceReviewPipeline(profile *models.Profile, hosts []models.AliveHost, finalSubdomains []string) ([]models.SecretFinding, error) {
	log.Printf("[*] [Target: %s] Starting Phase 4: Source-Review Native Pipeline...", profile.Domain)

	uniqueJSURLs := make(map[string]bool)
	var historicalURLs []string 

	log.Printf("[*] [Target: %s] Executing Gau...", profile.Domain)
	gauCmd := exec.Command("gau", "--json", "--subs", profile.Domain)
	var gauOut bytes.Buffer
	gauCmd.Stdout = &gauOut
	if err := gauCmd.Run(); err == nil {
		scanner := bufio.NewScanner(&gauOut)
		for scanner.Scan() {
			var res GauResult
			if err := json.Unmarshal(scanner.Bytes(), &res); err == nil {
				if isJSFile(res.Url) {
					historicalURLs = append(historicalURLs, res.Url)
				}
			}
		}
	}

	var unvalidatedJS []string
	unvalidatedJS = append(unvalidatedJS, historicalURLs...)

	if len(unvalidatedJS) > 0 {
		log.Printf("[*] [Target: %s] Validating %d historical JS URLs via Httpx...", profile.Domain, len(unvalidatedJS))
		httpxCmd := exec.Command("httpx", "-silent", "-mc", "200")
		httpxCmd.Stdin = strings.NewReader(strings.Join(unvalidatedJS, "\n"))
		var httpxOut bytes.Buffer
		httpxCmd.Stdout = &httpxOut
		if err := httpxCmd.Run(); err == nil {
			scanner := bufio.NewScanner(&httpxOut)
			for scanner.Scan() {
				aliveURL := strings.TrimSpace(scanner.Text())
				if aliveURL != "" && !uniqueJSURLs[aliveURL] {
					uniqueJSURLs[aliveURL] = true
				}
			}
		}
	}

	log.Printf("[*] [Target: %s] Executing Katana active crawling...", profile.Domain)
	katanaCmd := exec.Command("katana", "-silent", "-j", "-d", "2")
	
	var aliveHostsList []string
	for _, h := range hosts {
		aliveHostsList = append(aliveHostsList, h.URL)
	}
	katanaCmd.Stdin = strings.NewReader(strings.Join(aliveHostsList, "\n"))
	
	var katanaOut bytes.Buffer
	katanaCmd.Stdout = &katanaOut
	if err := katanaCmd.Run(); err == nil {
		scanner := bufio.NewScanner(&katanaOut)
		for scanner.Scan() {
			var res KatanaResult
			if err := json.Unmarshal(scanner.Bytes(), &res); err == nil {
				url := res.Request.Endpoint
				if isJSFile(url) && url != "" && !uniqueJSURLs[url] {
					uniqueJSURLs[url] = true
				}
			}
		}
	}

	log.Printf("[*] [Target: %s] Executing Subjs...", profile.Domain)
	subjsCmd := exec.Command("subjs")
	subjsCmd.Stdin = strings.NewReader(strings.Join(aliveHostsList, "\n"))
	var subjsOut bytes.Buffer
	subjsCmd.Stdout = &subjsOut
	if err := subjsCmd.Run(); err == nil {
		scanner := bufio.NewScanner(&subjsOut)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url != "" && !uniqueJSURLs[url] {
				uniqueJSURLs[url] = true
			}
		}
	}

	var finalLiveJS []string
	for url := range uniqueJSURLs {
		finalLiveJS = append(finalLiveJS, url)
	}

	if len(finalLiveJS) == 0 {
		log.Printf("[-] [Target: %s] No active JS files discovered for source reviewing.", profile.Domain)
		return nil, nil
	}
	log.Printf("[+] [Target: %s] Feeding %d live JS files into secret scanners...", profile.Domain, len(finalLiveJS))

	var secrets []models.SecretFinding
	uniqueSecrets := make(map[string]bool)

	mantraCmd := exec.Command("mantra", "-j")
	mantraCmd.Stdin = strings.NewReader(strings.Join(finalLiveJS, "\n"))
	var mantraOut bytes.Buffer
	mantraCmd.Stdout = &mantraOut
	if err := mantraCmd.Run(); err == nil {
		scanner := bufio.NewScanner(&mantraOut)
		for scanner.Scan() {
			var res MantraResult
			if err := json.Unmarshal(scanner.Bytes(), &res); err == nil {
				sig := res.Type + "|" + res.Secret
				if !uniqueSecrets[sig] {
					uniqueSecrets[sig] = true
					secrets = append(secrets, models.SecretFinding{
						ProfileID:   profile.ID,
						SecretType:  res.Type,
						SecretValue: res.Secret,
						SourceURL:   "mantra-discovery", 
					})
				}
			}
		}
	}

	tmpFile, err := os.CreateTemp("", "js_targets*.txt")
	if err == nil {
		defer os.Remove(tmpFile.Name())
		tmpFile.WriteString(strings.Join(finalLiveJS, "\n"))
		tmpFile.Close()

		sfCmd := exec.Command("secretfinder.py", "-i", tmpFile.Name())
		var sfOut bytes.Buffer
		sfCmd.Stdout = &sfOut
		if err := sfCmd.Run(); err == nil {
			var currentURL string
			scanner := bufio.NewScanner(&sfOut)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "URL:") {
					currentURL = strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
				} else if strings.HasPrefix(line, "->") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						secType := strings.TrimSpace(strings.TrimPrefix(parts[0], "->"))
						secVal := strings.TrimSpace(parts[1])
						
						sig := secType + "|" + secVal
						if !uniqueSecrets[sig] {
							uniqueSecrets[sig] = true
							secrets = append(secrets, models.SecretFinding{
								ProfileID:   profile.ID,
								SecretType:  secType,
								SecretValue: secVal,
								SourceURL:   currentURL,
							})
						}
					}
				}
			}
		}
	}

	log.Printf("[+] [Target: %s] Source review complete. %d potential secrets found.", profile.Domain, len(secrets))
	return secrets, nil
}
