package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type HttpxResult struct {
	URL        string   `json:"url"`
	Host       string   `json:"host"`
	A          []string `json:"a"`
	Title      string   `json:"title"`
	WebServer  string   `json:"webserver"`
	StatusCode int      `json:"status_code"`
	Failed     bool     `json:"failed"`
}

// RunHttpx probes the given names and returns the ones that answered.
//
// The results and the error are both meaningful: httpx streams JSONL as it
// probes, so a run that failed or hit its timeout still returns every host it
// had already confirmed alive.
func RunHttpx(profile *models.Profile, subdomains []string) ([]models.AliveHost, error) {
	if len(subdomains) == 0 {
		return nil, fmt.Errorf("no input subdomains provided to RunHttpx")
	}

	log.Printf("[*] [Target: %s] Running httpx against %d endpoint(s)...", profile.Domain, len(subdomains))

	args := []string{"-silent", "-json", "-title", "-web-server", "-ip", "-status-code"}
	stdin := strings.NewReader(strings.Join(subdomains, "\n"))

	outb, err := runTool("httpx", args, stdin, timeoutHttpx)

	return parseHttpxOutput(outb, profile.ID), err
}

// parseHttpxOutput reads httpx's JSONL, skipping unparseable lines so a
// truncated final line from a killed process does not discard the run.
func parseHttpxOutput(out *bytes.Buffer, profileID uuid.UUID) []models.AliveHost {
	if out == nil {
		return nil
	}

	var aliveHosts []models.AliveHost
	uniqueURLs := make(map[string]bool)

	scanner := newLineScanner(out)
	for scanner.Scan() {
		var result HttpxResult
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			continue
		}

		if !result.Failed && result.URL != "" && !uniqueURLs[result.URL] {
			uniqueURLs[result.URL] = true

			aliveHosts = append(aliveHosts, models.AliveHost{
				ProfileID:  profileID,
				URL:        result.URL,
				IP:         strings.Join(result.A, ", "),
				Title:      result.Title,
				WebServer:  result.WebServer,
				StatusCode: result.StatusCode,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[-] Stopped reading httpx output early: %v", err)
	}

	return aliveHosts
}
