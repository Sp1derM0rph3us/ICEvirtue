package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

const DefaultWAFProcessTimeout = 30 * time.Second

// wafObservation is emitted only when WAFW00F produced a valid result. A failed
// invocation must not overwrite the last successful observation with "none".
type wafObservation struct {
	URL  string
	Name string
}

type wafw00fRecord struct {
	URL      string `json:"url"`
	Detected bool   `json:"detected"`
	Firewall string `json:"firewall"`
}

func parseWAFW00FOutput(out io.Reader) (string, error) {
	if out == nil {
		return "", errors.New("empty WAFW00F output")
	}
	var records []wafw00fRecord
	decoder := json.NewDecoder(out)
	if err := decoder.Decode(&records); err != nil {
		return "", fmt.Errorf("invalid WAFW00F JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			err = errors.New("additional JSON value")
		}
		return "", fmt.Errorf("invalid WAFW00F JSON: %w", err)
	}
	if len(records) != 1 {
		return "", fmt.Errorf("expected one WAFW00F result, got %d", len(records))
	}
	record := records[0]
	if !record.Detected {
		if !strings.EqualFold(strings.TrimSpace(record.Firewall), "none") {
			return "", errors.New("inconsistent WAFW00F no-detection result")
		}
		return "none", nil
	}
	name := strings.TrimSpace(record.Firewall)
	if name == "" || strings.EqualFold(name, "none") {
		return "", errors.New("WAFW00F detection has no product name")
	}
	if strings.EqualFold(name, "generic") {
		return "Unknown WAF", nil
	}
	return name, nil
}

func (run *runner) detectWAF(endpoint string, processTimeout time.Duration) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("invalid HTTP endpoint for WAF detection")
	}
	// WAFW00F's default is first prioritized product match. -r prevents a
	// redirect from silently probing a different, possibly out-of-scope host.
	out, err := run.runTool("wafw00f", []string{"-r", "--no-colors", "-o", "-", "-f", "json", endpoint}, nil, processTimeout)
	defer out.Close()
	if err != nil {
		return "", err
	}
	return parseWAFW00FOutput(out)
}

// RunWAFDetection scans every HTTPX-confirmed endpoint, including statuses not
// forwarded to the later fuzzing and Nuclei stages. Parallelism is bounded so
// large profiles do not launch one Python process per asset simultaneously.
func (run *runner) RunWAFDetection(hosts []models.AliveHost) ([]wafObservation, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	if _, err := run.tools.resolveTool("wafw00f"); err != nil {
		return nil, err
	}
	processTimeout := run.wafTimeout
	const workers = 4
	type result struct {
		index int
		name  string
		err   error
	}
	jobs := make(chan int)
	results := make(chan result, len(hosts))
	var wg sync.WaitGroup
	for i := 0; i < workers && i < len(hosts); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				name, err := run.detectWAF(hosts[index].URL, processTimeout)
				results <- result{index: index, name: name, err: err}
			}
		}()
	}
	for i := range hosts {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(results)

	byIndex := make([]*wafObservation, len(hosts))
	failed := 0
	for result := range results {
		if result.err != nil {
			failed++
			log.Printf("[-] WAF detection failed for %s: %v", hosts[result.index].URL, result.err)
			continue
		}
		byIndex[result.index] = &wafObservation{URL: hosts[result.index].URL, Name: result.name}
	}
	observations := make([]wafObservation, 0, len(hosts)-failed)
	for _, observation := range byIndex {
		if observation != nil {
			observations = append(observations, *observation)
		}
	}
	if failed > 0 {
		return observations, fmt.Errorf("%d of %d WAF probe(s) failed", failed, len(hosts))
	}
	return observations, nil
}
