package engine

import (
	"bytes"
	"log"
	"strings"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// RunAmass enumerates subdomains with OWASP Amass.
//
// The results and the error are both meaningful: amass streams its findings, so
// a run that failed or hit its timeout still returns what it emitted first.
func RunAmass(profile *models.Profile) ([]string, error) {
	log.Printf("[*] [Target: %s] Running amass...", profile.Domain)

	args := []string{"enum", "-d", profile.Domain, "-nocolor"}

	outb, err := runTool("amass", args, nil, timeoutAmass)

	return parseAmassOutput(outb, profile.Domain), err
}

// parseAmassOutput keeps the lines that look like subdomains of the target and
// ignores everything else amass prints.
func parseAmassOutput(out *bytes.Buffer, domain string) []string {
	if out == nil {
		return nil
	}

	unique := make(map[string]bool)
	var results []string

	scanner := newLineScanner(out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasSuffix(line, domain) && !unique[line] {
			unique[line] = true
			results = append(results, line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[-] Stopped reading amass output early: %v", err)
	}

	return results
}
