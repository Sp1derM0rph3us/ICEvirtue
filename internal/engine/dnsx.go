package engine

import (
	"bytes"
	"fmt"
	"log"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// RunDnsx bruteforces subdomains against a single wordlist.
//
// The results and the error are both meaningful: dnsx streams resolved names, so
// a run that failed or hit its timeout still returns what it resolved first.
func RunDnsx(profile *models.Profile, wordlistPath string) ([]string, error) {
	if wordlistPath == "" {
		return nil, fmt.Errorf("no wordlist provided for dnsx")
	}

	log.Printf("[*] [Target: %s] Running dnsx with wordlist: %s", profile.Domain, wordlistPath)

	args := []string{"-silent", "-d", profile.Domain, "-w", wordlistPath, "-resp-only"}

	outb, err := runTool("dnsx", args, nil, timeoutDnsx)

	return parseDnsxOutput(outb), err
}

// parseDnsxOutput reads dnsx's plain one-name-per-line output.
func parseDnsxOutput(out *bytes.Buffer) []string {
	if out == nil {
		return nil
	}

	unique := make(map[string]bool)
	var results []string

	scanner := newLineScanner(out)
	for scanner.Scan() {
		sub := scanner.Text()
		if sub != "" && !unique[sub] {
			unique[sub] = true
			results = append(results, sub)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[-] Stopped reading dnsx output early: %v", err)
	}

	return results
}
