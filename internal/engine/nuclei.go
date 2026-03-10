package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type NucleiResult struct {
	Info struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
	TemplateID  string `json:"template-id"`
	MatchedAt   string `json:"matched-at"`
	Host        string `json:"host"`
}

func RunNuclei(profile *models.Profile, hosts []models.AliveHost) ([]models.Vulnerability, error) {
	log.Printf("[*] [Target: %s] Starting Phase 3: Nuclei Vulnerability Scan (%d hosts)...", profile.Domain, len(hosts))

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no live hosts provided to RunNuclei")
	}

	var urls []string
	for _, h := range hosts {
		urls = append(urls, h.URL)
	}

	args := []string{"-silent", "-jsonl"}
	cmd := exec.Command("nuclei", args...)

	cmd.Stdin = strings.NewReader(strings.Join(urls, "\n"))

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("nuclei execution failed: %v. Stderr: %s", err, errb.String())
	}

	var vulnerabilities []models.Vulnerability
	uniqueVulns := make(map[string]bool)

	scanner := bufio.NewScanner(&outb)
	for scanner.Scan() {
		line := scanner.Bytes()

		var result NucleiResult
		if err := json.Unmarshal(line, &result); err != nil {
			log.Printf("[-] Failed to parse Nuclei JSON line: %v", err)
			continue
		}

		sig := fmt.Sprintf("%s|%s", result.TemplateID, result.MatchedAt)
		
		if !uniqueVulns[sig] && result.TemplateID != "" {
			uniqueVulns[sig] = true
			
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				ProfileID:   profile.ID,
				TemplateID:  result.TemplateID,
				URL:         result.MatchedAt,
				Severity:    result.Info.Severity,
				Name:        result.Info.Name,
				Description: result.Info.Description,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading nuclei output: %v", err)
	}

	log.Printf("[+] [Target: %s] Nuclei scan finished, discovered %d potential findings", profile.Domain, len(vulnerabilities))
	return vulnerabilities, nil
}
