package engine

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// RunDnsx bruteforces subdomains against a single wordlist.
//
// The results and the error are both meaningful: dnsx streams resolved names, so
// a run that failed or hit its timeout still returns what it resolved first.
func (run *runner) RunDnsx(profile *models.Profile, wordlistPath string) ([]string, error) {
	if wordlistPath == "" {
		return nil, fmt.Errorf("no wordlist provided for dnsx")
	}

	log.Printf("[*] [Target: %s] Running dnsx with wordlist: %s", profile.Domain, wordlistPath)

	// Preserve uploaded bytes for hashing; normalize only a private scan copy.
	dir, err := os.MkdirTemp(run.scratch, "icevirtue-dnsx-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	normalized := filepath.Join(dir, filepath.Base(wordlistPath))
	if err = run.normalizeDNSXList(wordlistPath, normalized); err != nil {
		return nil, err
	}
	args := []string{"-silent", "-d", profile.Domain, "-w", normalized}

	outb, err := run.runTool("dnsx", args, nil, toolTimeout(run.config.Tools.DNSXTimeoutMinutes))

	defer outb.Close()
	results, parseErr := parseDnsxOutput(outb)
	return results, errors.Join(err, parseErr)
}

// parseDnsxOutput reads dnsx's plain one-name-per-line output.
func parseDnsxOutput(out io.Reader) ([]string, error) {
	if out == nil {
		return nil, nil
	}

	unique := make(map[string]bool)
	var results []string

	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 4096), 4096)
	for scanner.Scan() {
		sub := scanner.Text()
		if len(sub) > 253 {
			return results, fmt.Errorf("DNSX returned a name longer than 253 bytes")
		}
		if sub != "" && !unique[sub] {
			if len(results) >= 100000 {
				return results, fmt.Errorf("DNSX discovery limit of 100000 unique names reached; partial results retained")
			}
			unique[sub] = true
			results = append(results, sub)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[-] Stopped reading dnsx output early: %v", err)
	}

	return results, scanner.Err()
}

func (run *runner) normalizeDNSXList(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(output)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 4098)
	for scanner.Scan() {
		if err = run.ctx.Err(); err != nil {
			break
		}
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		if _, err = writer.WriteString(word + "\n"); err != nil {
			break
		}
	}
	return errors.Join(err, scanner.Err(), writer.Flush(), output.Close())
}
