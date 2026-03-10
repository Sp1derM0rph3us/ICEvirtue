package engine

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func RunAmass(profile *models.Profile) ([]string, error) {
	log.Printf("[*] [Target: %s] Starting OWASP Amass passive enumeration...", profile.Domain)

	args := []string{"enum", "-d", profile.Domain, "-nocolor"}
	cmd := exec.Command("amass", args...)

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("amass execution failed: %v. Stderr: %s", err, errb.String())
	}

	uniqueSubdomains := make(map[string]bool)
	var results []string

	scanner := bufio.NewScanner(&outb)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		if strings.HasSuffix(line, profile.Domain) && !uniqueSubdomains[line] {
			uniqueSubdomains[line] = true
			results = append(results, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading amass output: %v", err)
	}

	log.Printf("[+] [Target: %s] Amass discovered %d unique subdomains", profile.Domain, len(results))
	return results, nil
}
