package engine

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// WaymoreResponseLimit is a count, matching waymore's -l flag, not a byte size.
var WaymoreResponseLimit = 5000
var WaymoreConfig string

const archiveURLPattern = `(?i)\.(?:js|json|ts|tsx)(?:[?#]|$)`

var archiveHashPattern = regexp.MustCompile(`^[0-9]+$`)

type archiveEvidence struct {
	OriginalURL string
	ArchiveURL  string
}

type jsSources struct {
	live     []string
	archived map[string][]archiveEvidence // downloaded file -> original URLs/captures
	cleanup  func()
}

func collectWaymore(profile *models.Profile) ([]string, map[string][]archiveEvidence, func(), error) {
	dir, err := os.MkdirTemp("", "icevirtue-waymore-")
	if err != nil {
		return nil, nil, func() {}, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	urlFile := filepath.Join(dir, "urls.txt")
	responses := filepath.Join(dir, "responses")
	if err := os.Mkdir(responses, 0700); err != nil {
		return nil, nil, cleanup, err
	}
	config := WaymoreConfig
	if config == "" {
		config = filepath.Join(dir, "config.yml")
		// Waymore's stock FILTER_URL excludes paths such as /jquery and /bootstrap.
		// A nonempty sentinel avoids an empty regular expression matching every URL.
		body := "FILTER_CODE: 404\nFILTER_MIME: image/,font/,audio/,video/,application/octet-stream\n" +
			"FILTER_URL: __ICEVIRTUE_NO_URL_EXCLUSION__\nFILTER_KEYWORDS:\n" +
			"URLSCAN_API_KEY:\nVIRUSTOTAL_API_KEY:\nINTELX_API_KEY:\n" +
			"CONTINUE_RESPONSES_IF_PIPED: False\n"
		if err := os.WriteFile(config, []byte(body), 0600); err != nil {
			return nil, nil, cleanup, err
		}
	}
	limit := WaymoreResponseLimit
	if limit <= 0 {
		limit = 5000
	}
	args := []string{"-i", profile.Domain, "-mode", "B", "-oU", urlFile,
		"-oR", responses, "-ow", "-ci", "d", "-l", strconv.Itoa(limit),
		"-ra", archiveURLPattern, "-f", "-c", config}
	log.Printf("[*] [Target: %s] Running waymore with a %d response limit...", profile.Domain, limit)
	runErr := runToolToFiles("waymore", args, timeoutWaymore)
	urls, urlErr := readWaymoreURLs(urlFile, profile.Domain)
	archived, indexErr := readWaymoreIndex(responses, profile.Domain)
	return urls, archived, cleanup, errors.Join(runErr, urlErr, indexErr)
}

func inScopeURL(raw, domain string) bool {
	if !validHTTPURL(raw) {
		return false
	}
	u, _ := url.Parse(raw)
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func isArchiveFileURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	for _, ext := range jsExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func readWaymoreURLs(path, domain string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var urls []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if inScopeURL(raw, domain) && isArchiveFileURL(raw) && !seen[raw] {
			seen[raw] = true
			urls = append(urls, raw)
		}
	}
	return urls, scanner.Err()
}

func readWaymoreIndex(dir, domain string) (map[string][]archiveEvidence, error) {
	result := make(map[string][]archiveEvidence)
	files, err := os.ReadDir(dir)
	if err != nil {
		return result, err
	}
	byName := make(map[string]string)
	for _, entry := range files {
		if !entry.Type().IsRegular() {
			continue
		}
		name := entry.Name()
		if hash, _, ok := strings.Cut(name, "."); ok && archiveHashPattern.MatchString(hash) {
			byName[name] = filepath.Join(dir, name)
		}
	}
	indexPath := filepath.Join(dir, "waymore_index.txt")
	f, err := os.Open(indexPath)
	if os.IsNotExist(err) {
		f, err = os.Open(filepath.Join(dir, "index.txt"))
	}
	if os.IsNotExist(err) {
		if len(byName) > 0 {
			return result, fmt.Errorf("waymore saved %d response file(s) without a capture index", len(byName))
		}
		return result, nil
	}
	if err != nil {
		return result, err
	}
	defer f.Close()
	var bad int
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		hash, rest, ok := strings.Cut(line, ",")
		if !ok || !archiveHashPattern.MatchString(hash) {
			bad++
			continue
		}
		separator := strings.LastIndex(rest, ",")
		if separator < 0 {
			bad++
			continue
		}
		ref, ok := parseArchiveEvidence(strings.TrimSpace(rest[:separator]))
		if !ok || !inScopeURL(ref.OriginalURL, domain) || !isArchiveFileURL(ref.OriginalURL) {
			bad++
			continue
		}
		// Waymore preserves URL extension case and escapes when naming files.
		// Python's urlparse also separates parameters from the final path segment.
		u, _ := url.Parse(ref.OriginalURL) // validated above
		base := path.Base(u.EscapedPath())
		base, _, _ = strings.Cut(base, ";")
		ext := path.Ext(base)
		// An encoded or otherwise nonstandard extension may trigger Waymore's
		// MIME fallback; the index lacks the MIME needed to reconstruct that name.
		knownExtension := false
		for _, allowed := range jsExtensions {
			if strings.ToLower(ext) == allowed {
				knownExtension = true
				break
			}
		}
		file, exists := byName[hash+ext]
		if !knownExtension || !exists {
			bad++
			continue
		}
		// Same-hash, same-extension overwrites in Waymore cannot be detected
		// from its index, which records neither a strong digest nor a filename.
		duplicate := false
		for _, existing := range result[file] {
			if existing.OriginalURL == ref.OriginalURL {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result[file] = append(result[file], ref)
		}
	}
	if bad > 0 {
		err = errors.Join(err, fmt.Errorf("waymore returned %d invalid or unmappable capture(s)", bad))
	}
	return result, errors.Join(err, scanner.Err())
}

func parseArchiveEvidence(raw string) (archiveEvidence, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return archiveEvidence{}, false
	}
	switch strings.ToLower(u.Hostname()) {
	case "web.archive.org":
		if !strings.HasPrefix(u.Path, "/web/") {
			return archiveEvidence{}, false
		}
		at := strings.Index(raw, "/http")
		if at < 0 {
			return archiveEvidence{}, false
		}
		return archiveEvidence{OriginalURL: raw[at+1:], ArchiveURL: raw}, true
	case "urlscan.io":
		if !strings.HasPrefix(u.Path, "/dom/") {
			return archiveEvidence{}, false
		}
		at := strings.Index(raw, "/http")
		if at < 0 {
			return archiveEvidence{}, false
		}
		return archiveEvidence{OriginalURL: raw[at+1:], ArchiveURL: raw[:at+1]}, true
	case "ghostarchive.org":
		original, err := url.QueryUnescape(u.Fragment)
		if err != nil || !validHTTPURL(original) {
			return archiveEvidence{}, false
		}
		return archiveEvidence{OriginalURL: original, ArchiveURL: strings.SplitN(raw, "#", 2)[0]}, true
	}
	return archiveEvidence{}, false
}
