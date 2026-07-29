package engine

import (
	"bytes"
	"encoding/json"
	"log"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type SubfinderResult struct {
	Host   string `json:"host"`
	Source string `json:"source"`
}

// RunSubfinder enumerates subdomains passively.
//
// The results and the error are both meaningful. Subfinder streams JSONL, so a
// run that failed or hit its timeout partway through still returns every name it
// managed to emit, and the caller decides what a partial run is worth.
func RunSubfinder(profile *models.Profile) ([]string, error) {
	log.Printf("[*] [Target: %s] Running subfinder...", profile.Domain)

	args := []string{"-d", profile.Domain, "-silent", "-json"}

	if profile.Mode == "full" {
		args = append(args, "-all")
	}

	outb, err := runTool("subfinder", args, nil, timeoutSubfinder)

	return parseSubfinderOutput(outb), err
}

// parseSubfinderOutput reads subfinder's JSONL. Unparseable lines are counted and
// skipped rather than aborting, because a process killed mid-write leaves a
// truncated final line that must not discard the rest of the run.
func parseSubfinderOutput(out *bytes.Buffer) []string {
	if out == nil {
		return nil
	}

	unique := make(map[string]bool)
	var results []string
	malformed := 0

	scanner := newLineScanner(out)
	for scanner.Scan() {
		var result SubfinderResult
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			malformed++
			continue
		}

		if result.Host != "" && !unique[result.Host] {
			unique[result.Host] = true
			results = append(results, result.Host)
		}
	}

	if malformed > 0 {
		log.Printf("[-] Skipped %d unparseable subfinder output line(s)", malformed)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[-] Stopped reading subfinder output early: %v", err)
	}

	return results
}
