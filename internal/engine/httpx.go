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

type HttpxResult struct {
	URL       string `json:"url"`
	Host      string `json:"host"`
	A         []string `json:"a"`
	Title     string `json:"title"`
	WebServer string `json:"webserver"`
	StatusCode int   `json:"status-code"`
	Failed    bool   `json:"failed"`
}

func RunHttpx(profile *models.Profile, subdomains []string) ([]models.AliveHost, error) {
	log.Printf("[*] [Target: %s] Starting Phase 2: Httpx (Probing %d endpoints)...", profile.Domain, len(subdomains))

	if len(subdomains) == 0 {
		return nil, fmt.Errorf("no input subdomains provided to RunHttpx")
	}

	args := []string{"-silent", "-json", "-title", "-web-server", "-ip", "-status-code"}
	cmd := exec.Command("httpx", args...)

	cmd.Stdin = strings.NewReader(strings.Join(subdomains, "\n"))

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("httpx execution failed: %v. Stderr: %s", err, errb.String())
	}

	var aliveHosts []models.AliveHost
	uniqueURLs := make(map[string]bool)

	scanner := bufio.NewScanner(&outb)
	for scanner.Scan() {
		line := scanner.Bytes()
		
		var result HttpxResult
		if err := json.Unmarshal(line, &result); err != nil {
			continue 
		}

		if !result.Failed && result.URL != "" && !uniqueURLs[result.URL] {
			uniqueURLs[result.URL] = true
			
			aliveHosts = append(aliveHosts, models.AliveHost{
				ProfileID: profile.ID,
				URL:       result.URL,
				IP:        strings.Join(result.A, ", "),
				Title:     result.Title,
				WebServer: result.WebServer,
				StatusCode: result.StatusCode,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading httpx output: %v", err)
	}

	log.Printf("[+] [Target: %s] Httpx discovered %d alive hosts", profile.Domain, len(aliveHosts))
	return aliveHosts, nil
}
