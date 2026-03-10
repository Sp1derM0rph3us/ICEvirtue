package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type SubfinderResult struct {
	Host   string `json:"host"`
	Source string `json:"source"`
}

func RunSubfinder(profile *models.Profile) ([]string, error) {
	log.Printf("[*] [Target: %s] Starting Phase 1: Subfinder...", profile.Domain)

	args := []string{"-d", profile.Domain, "-silent", "-json"}

	if profile.Mode == "full" {
		args = append(args, "-all") 
	}

	cmd := exec.Command("subfinder", args...)

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("subfinder execution failed: %v. Stderr: %s", err, errb.String())
	}

	uniqueSubdomains := make(map[string]bool)
	var results []string

	scanner := bufio.NewScanner(&outb)
	for scanner.Scan() {
		line := scanner.Bytes()
		
		var result SubfinderResult
		if err := json.Unmarshal(line, &result); err != nil {
			log.Printf("[-] Failed to parse subfinder JSON line: %v", err)
			continue
		}

		if result.Host != "" && !uniqueSubdomains[result.Host] {
			uniqueSubdomains[result.Host] = true
			results = append(results, result.Host)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading subfinder output: %v", err)
	}

	log.Printf("[+] [Target: %s] Subfinder discovered %d unique subdomains", profile.Domain, len(results))
	return results, nil
}
