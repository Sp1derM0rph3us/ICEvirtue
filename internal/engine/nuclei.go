package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/google/uuid"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type NucleiResult struct {
	Info struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Host       string `json:"host"`
}

// RunNuclei scans the given hosts for known vulnerabilities.
//
// The results and the error are both meaningful: nuclei streams JSONL per match,
// so a run that failed or hit its timeout still returns every finding it had
// already reported. On a two hour budget that is usually most of them.
func (run *runner) RunNuclei(profile *models.Profile, hosts []models.AliveHost) ([]models.Vulnerability, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no live hosts provided to RunNuclei")
	}

	log.Printf("[*] [Target: %s] Running nuclei against %d host(s)...", profile.Domain, len(hosts))

	var urls []string
	for _, h := range hosts {
		urls = append(urls, h.URL)
	}

	// Stage 04 timed out at its 2h budget largely because hosts behind Azure
	// Front Door returned 400s on reset connections and were retried rather than
	// abandoned. -mhe drops a host after this many transport errors, reclaiming
	// that wasted time without narrowing template coverage or dropping findings.
	args := []string{"-silent", "-jsonl", "-mhe", "15"}
	stdin := strings.NewReader(strings.Join(urls, "\n"))

	outb, err := run.runTool("nuclei", args, stdin, toolTimeout(run.config.Tools.NucleiTimeoutMinutes))

	defer outb.Close()
	results, parseErr := parseNucleiOutput(outb, profile.ID)
	return results, errors.Join(err, parseErr)
}

// parseNucleiOutput reads nuclei's JSONL, skipping unparseable lines so a
// truncated final line from a killed process does not discard the run.
func parseNucleiOutput(out io.Reader, profileID uuid.UUID) ([]models.Vulnerability, error) {
	if out == nil {
		return nil, nil
	}

	var vulnerabilities []models.Vulnerability
	uniqueVulns := make(map[string]bool)

	scanner := newLineScanner(out)
	for scanner.Scan() {
		var result NucleiResult
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			continue
		}

		sig := fmt.Sprintf("%s|%s", result.TemplateID, result.MatchedAt)

		if !uniqueVulns[sig] && result.TemplateID != "" {
			uniqueVulns[sig] = true

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				ProfileID:   profileID,
				TemplateID:  result.TemplateID,
				URL:         result.MatchedAt,
				Severity:    result.Info.Severity,
				Name:        result.Info.Name,
				Description: result.Info.Description,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[-] Stopped reading nuclei output early: %v", err)
	}

	return vulnerabilities, scanner.Err()
}
