package engine

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func RunDnsx(profile *models.Profile, wordlistPath string) ([]string, error) {
	log.Printf("[*] [Target: %s] Starting dnsx active bruteforce with wordlist: %s", profile.Domain, wordlistPath)

	if wordlistPath == "" {
		return nil, fmt.Errorf("no wordlist provided for dnsx")
	}

	args := []string{"-silent", "-d", profile.Domain, "-w", wordlistPath, "-resp-only"}
	cmd := exec.Command("dnsx", args...)

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("dnsx execution failed: %v. Stderr: %s", err, errb.String())
	}

	uniqueSubdomains := make(map[string]bool)
	var results []string

	scanner := bufio.NewScanner(&outb)
	for scanner.Scan() {
		sub := scanner.Text()
		if sub != "" && !uniqueSubdomains[sub] {
			uniqueSubdomains[sub] = true
			results = append(results, sub)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading dnsx output: %v", err)
	}

	log.Printf("[+] [Target: %s] dnsx discovered %d valid subdomains", profile.Domain, len(results))
	return results, nil
}
