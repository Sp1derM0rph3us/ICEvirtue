package engine

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ToolPaths pins a tool to an exact binary, as a comma-separated list of
// name=path pairs. Wired to --tool-paths.
var ToolPaths string

// versionProbeTimeout bounds the identity probe. Asking a tool for its version
// is meant to be instant, so anything slower is not answering.
const versionProbeTimeout = 15 * time.Second

// versionPattern matches the version number a goflags-based tool prints for
// -version, for example "Current Version: v2.12.0".
var versionPattern = regexp.MustCompile(`v?\d+\.\d+`)

// ansiPattern strips the colour codes these tools emit, so a rejected candidate
// can be quoted in a log line without garbage.
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// toolSpec says how to locate one tool's binary.
type toolSpec struct {
	// names to try, in order.
	//
	// Debian and its derivatives cannot ship projectdiscovery's httpx as "httpx"
	// because the python3-httpx package already owns that name, so they ship it
	// as httpx-toolkit instead. Listing the alternatives keeps discovery working
	// without the engine needing to know which distribution it is running on: a
	// name that does not exist simply does not resolve.
	names []string

	// verify requires a candidate to pass the -version probe before it is
	// accepted. Resolving a name is not enough to know it is the right program.
	verify bool
}

// Only the goflags-based tools are verified, because -version is a property of
// that shared flag library. The rest are located by name alone.
var toolSpecs = map[string]toolSpec{
	"subfinder":       {names: []string{"subfinder"}, verify: true},
	"httpx":           {names: []string{"httpx", "httpx-toolkit", "httpx-pd"}, verify: true},
	"dnsx":            {names: []string{"dnsx", "dnsx-toolkit"}, verify: true},
	"nuclei":          {names: []string{"nuclei", "nuclei-toolkit"}, verify: true},
	"katana":          {names: []string{"katana", "katana-toolkit"}, verify: true},
	"amass":           {names: []string{"amass"}},
	"gau":             {names: []string{"gau"}},
	"subjs":           {names: []string{"subjs"}},
	"mantra":          {names: []string{"mantra"}},
	"secretfinder.py": {names: []string{"secretfinder.py", "SecretFinder.py"}},
}

// resolution is the cached outcome of locating one tool.
type resolution struct {
	Path string
	Err  error
	// Note explains why the choice is doubtful, and is empty when it is not.
	Note string
}

var (
	toolPathMu    sync.Mutex
	toolPathCache = map[string]resolution{}
)

// resolveTool finds the binary for a logical tool name, caching the outcome so
// the identity probe runs at most once per tool per process.
func resolveTool(tool string) (string, error) {
	toolPathMu.Lock()
	defer toolPathMu.Unlock()

	if r, ok := toolPathCache[tool]; ok {
		return r.Path, r.Err
	}

	r := locateTool(tool)
	toolPathCache[tool] = r

	if r.Err == nil && r.Note != "" {
		log.Printf("[-] %s: %s", tool, r.Note)
	}

	return r.Path, r.Err
}

// cachedToolNote reports why an already-resolved tool is doubtful, or "" when it
// is not. Only meaningful after resolveTool has run for that tool.
func cachedToolNote(tool string) string {
	toolPathMu.Lock()
	defer toolPathMu.Unlock()

	return toolPathCache[tool].Note
}

func locateTool(tool string) resolution {
	if path, ok := overriddenToolPath(tool); ok {
		if _, err := exec.LookPath(path); err != nil {
			return resolution{Err: fmt.Errorf("%s: --tool-paths points at %s, which is not usable: %v", tool, path, err)}
		}
		return resolution{Path: path}
	}

	spec, ok := toolSpecs[tool]
	if !ok {
		spec = toolSpec{names: []string{tool}}
	}

	var resolved, rejected []string

	for _, name := range spec.names {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		resolved = append(resolved, path)

		if !spec.verify {
			return resolution{Path: path}
		}

		if err := verifyToolIdentity(path); err != nil {
			rejected = append(rejected, fmt.Sprintf("%s (%v)", path, err))
			continue
		}

		return resolution{Path: path}
	}

	if len(resolved) == 0 {
		return resolution{Err: fmt.Errorf("%s not found: install it and make sure it is on PATH (tried the name(s) %s; searched: %s)",
			tool, strings.Join(spec.names, ", "), os.Getenv("PATH"))}
	}

	// Something answered to the name but nothing looked like the real tool. Use
	// the first candidate anyway rather than refuse to run, in case the probe is
	// simply wrong about a working binary, but say so loudly. On Debian, Kali and
	// Parrot this is what a python3-httpx collision looks like.
	return resolution{
		Path: resolved[0],
		Note: fmt.Sprintf("no candidate passed the -version probe, falling back to %s. Rejected: %s. If that is the wrong program, install the real one or pin it with --tool-paths %s=/path/to/binary",
			resolved[0], strings.Join(rejected, "; "), tool),
	}
}

// overriddenToolPath reads --tool-paths, a comma-separated list of name=path.
func overriddenToolPath(tool string) (string, bool) {
	for _, pair := range splitList(ToolPaths) {
		name, path, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(name) == tool {
			if path = strings.TrimSpace(path); path != "" {
				return path, true
			}
		}
	}
	return "", false
}

// verifyToolIdentity asks a candidate binary for its version.
//
// Every goflags-based tool supports -version, exits 0 and prints a version
// number. A different program that merely shares the name is unlikely to do
// both: python3-httpx, which owns the name httpx on Debian, Kali and Parrot,
// exits 2 with "No such option". Checking behaviour rather than looking up
// package names keeps this working on any distribution.
func verifyToolIdentity(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "-version")
	cmd.Env = toolEnv()

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("-version failed: %v: %s", err, summarizeOutput(out.String()))
	}

	if !versionPattern.MatchString(out.String()) {
		return fmt.Errorf("-version printed no version number: %s", summarizeOutput(out.String()))
	}

	return nil
}

// summarizeOutput reduces a tool's output to something quotable in a log line.
func summarizeOutput(s string) string {
	s = ansiPattern.ReplaceAllString(s, "")
	s = strings.Join(strings.Fields(s), " ")

	if s == "" {
		return "<no output>"
	}
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}
