package engine

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func RunDirectoryFuzzing(profile *models.Profile, validHosts []models.AliveHost, wordlistPaths []string) ([]models.DirectoryFinding, error) {
	log.Printf("[*] [Target: %s] Starting Phase 2: Directory Fuzzing on %d valid hosts with %d wordlist(s)...", profile.Domain, len(validHosts), len(wordlistPaths))

	if len(validHosts) == 0 {
		return nil, fmt.Errorf("no valid hosts provided for directory fuzzing")
	}

	seen := make(map[string]bool)
	var words []string

	for _, wordlistPath := range wordlistPaths {
		file, err := os.Open(wordlistPath)
		if err != nil {
			log.Printf("[-] Failed to open directory wordlist %s: %v", wordlistPath, err)
			continue
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word != "" && !strings.HasPrefix(word, "#") && !seen[word] {
				seen[word] = true
				words = append(words, word)
			}
		}

		if err := scanner.Err(); err != nil {
			log.Printf("[-] Error reading directory wordlist %s: %v", wordlistPath, err)
		}
		file.Close()
	}

	if len(words) == 0 {
		return nil, fmt.Errorf("all directory wordlists are empty or unreadable")
	}

	log.Printf("[*] [Target: %s] Loaded %d unique words from %d wordlist(s)", profile.Domain, len(words), len(wordlistPaths))

	var findings []models.DirectoryFinding
	var mu sync.Mutex

	// Transport tuned for fast fuzzing
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     10 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects
		},
	}

	concurrencyLimit := 50
	sem := make(chan struct{}, concurrencyLimit)
	var wg sync.WaitGroup

	for _, host := range validHosts {
		baseURL := strings.TrimRight(host.URL, "/")

		for _, word := range words {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore

			go func(h models.AliveHost, w string) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore

				targetURL := fmt.Sprintf("%s/%s", baseURL, strings.TrimLeft(w, "/"))

				req, err := http.NewRequest("GET", targetURL, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "ICEvirtue-Fuzzer/1.0")

				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				status := resp.StatusCode
				if status == 200 || status == 301 || status == 302 || status == 403 || status == 405 {
					mu.Lock()
					findings = append(findings, models.DirectoryFinding{
						ProfileID:    profile.ID,
						SubdomainURL: h.URL,
						DirURL:       targetURL,
						StatusCode:   status,
					})
					mu.Unlock()
				}
			}(host, word)
		}
	}

	wg.Wait()

	log.Printf("[+] [Target: %s] Directory fuzzing discovered %d valid directories", profile.Domain, len(findings))
	return findings, nil
}
