package engine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ToolHome overrides where the external tools keep their config directories.
// Wired to the --tool-home flag.
var ToolHome string

// defaultToolHome is a var rather than a const so tests can point it at a temp
// directory instead of depending on the real permissions of /opt.
var defaultToolHome = "/opt/icevirtue"

// Per-tool wall-clock budgets. Without these a hung tool pins is_scanning=true
// forever, since the lock is only released when the phase returns. subfinder
// self-caps at 10 minutes so its budget must comfortably exceed that; amass and
// katana are the genuinely unbounded ones.
const (
	timeoutSubfinder    = 20 * time.Minute
	timeoutAmass        = 60 * time.Minute
	timeoutDnsx         = 30 * time.Minute
	timeoutHttpx        = 30 * time.Minute
	timeoutNuclei       = 120 * time.Minute
	timeoutGau          = 30 * time.Minute
	timeoutKatana       = 45 * time.Minute
	timeoutSubjs        = 15 * time.Minute
	timeoutMantra       = 30 * time.Minute
	timeoutSecretFinder = 30 * time.Minute
)

// maxStreamCapture bounds how much of a failing tool's output we keep for the
// error message, so a tool that floods a stream cannot exhaust memory.
const maxStreamCapture = 64 * 1024

var (
	toolHomeOnce     sync.Once
	resolvedToolHome string
)

// resolveToolHome returns a directory that exists and is writable so the
// goflags-based tools (subfinder, httpx, dnsx, nuclei, katana) can create their
// config directories.
//
// They cannot do this under systemd: a system service gets no $HOME and
// defaults to WorkingDirectory=/, so goflags resolves its config path relative
// to the CWD, fails to create it, and the tool exits 1 within ~25ms after
// printing "open subfinder/config.yaml: no such file or directory" to stdout.
func resolveToolHome() string {
	toolHomeOnce.Do(func() {
		candidate := ToolHome
		if candidate == "" {
			candidate = defaultToolHome
		}
		candidates := []string{candidate}

		if home, err := os.UserHomeDir(); err == nil && home != "" {
			candidates = append(candidates, home)
		}
		if cwd, err := os.Getwd(); err == nil {
			candidates = append(candidates, filepath.Join(cwd, ".icevirtue-home"))
		}
		candidates = append(candidates, filepath.Join(os.TempDir(), "icevirtue-home"))

		var rejected []string
		for _, dir := range candidates {
			if err := checkToolHome(dir); err != nil {
				rejected = append(rejected, fmt.Sprintf("%s (%v)", dir, err))
				continue
			}
			resolvedToolHome = dir
			break
		}

		// Warn about anything we had to skip, so a production box that quietly
		// fell back to a temp directory does not look like a healthy one.
		for _, r := range rejected {
			log.Printf("[-] Unusable tool config home, falling back: %s", r)
		}

		if resolvedToolHome == "" {
			log.Printf("[-] No writable tool config home found. External tools will fail; pass --tool-home to point at a writable directory.")
			return
		}

		log.Printf("[+] Tool config home: %s", resolvedToolHome)
	})
	return resolvedToolHome
}

// checkToolHome verifies that dir/.config exists and is genuinely writable.
// os.Stat is not enough here: a root-owned /opt/icevirtue looks perfectly fine
// to an unprivileged process right up until the tool tries to write.
func checkToolHome(dir string) error {
	if dir == "" {
		return errors.New("empty path")
	}

	configDir := filepath.Join(dir, ".config")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	probe, err := os.CreateTemp(configDir, ".icevirtue-probe-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	probe.Close()

	return os.Remove(name)
}

// toolEnv returns the parent environment with HOME and XDG_CONFIG_HOME forced
// onto a writable directory. os.UserConfigDir prefers XDG_CONFIG_HOME and falls
// back to $HOME/.config, so both have to be set to cover either branch.
func toolEnv() []string {
	home := resolveToolHome()
	if home == "" {
		return os.Environ()
	}

	parent := os.Environ()
	env := make([]string, 0, len(parent)+2)
	for _, kv := range parent {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=") {
			continue
		}
		env = append(env, kv)
	}

	return append(env, "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"))
}

// runTool executes an external recon tool and returns its stdout.
//
// The returned buffer is always non-nil, INCLUDING when the error is non-nil.
// Callers are expected to parse it either way: a tool that streamed thousands of
// results and then exited non-zero, or that was killed partway through by its
// timeout, has still produced everything in that buffer, and throwing it away
// loses most of a long enumeration run.
//
// On failure the error names the resolved binary, its arguments, the exit code,
// the elapsed time and the resolved HOME, and it reports BOTH streams. That
// last part matters: several of these tools print fatal startup errors to
// stdout rather than stderr, so reporting stderr alone leaves the operator
// staring at an empty message.
func runTool(name string, args []string, stdin io.Reader, timeout time.Duration) (*bytes.Buffer, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return &bytes.Buffer{}, fmt.Errorf("%s not found: install it and make sure it is on PATH (searched: %s)", name, os.Getenv("PATH"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = toolEnv()
	cmd.Stdin = stdin

	// Run the tool in its own process group and kill the whole group when the
	// deadline fires. Killing just the direct child is not enough: these tools
	// fan out to subprocesses that would survive, keep the output pipe open, and
	// leave cmd.Wait blocked long past the timeout — which is precisely the
	// stuck-scan the timeout exists to prevent.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	// Backstop in case something still holds a pipe open.
	cmd.WaitDelay = 10 * time.Second

	outb := &cappedBuffer{limit: maxStreamCapture}
	errb := &cappedBuffer{limit: maxStreamCapture}
	var stdout bytes.Buffer
	cmd.Stdout = io.MultiWriter(&stdout, outb)
	cmd.Stderr = errb

	start := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(start).Round(time.Millisecond)

	if runErr != nil {
		reason := runErr.Error()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			reason = fmt.Sprintf("timed out after %s", timeout)
		}

		return &stdout, fmt.Errorf("%s failed after %s (%s)\n  path:   %s\n  args:   %s\n  HOME:   %s\n  stderr: %s\n  stdout: %s",
			name, elapsed, reason, path, strings.Join(args, " "), resolveToolHome(),
			describeStream(errb.String()), describeStream(outb.String()))
	}

	return &stdout, nil
}

// newLineScanner returns a scanner sized for the long JSON lines some of these
// tools emit. bufio's 64KiB default silently stops the scan on a longer line,
// which would drop every remaining result rather than just the oversized one.
func newLineScanner(out *bytes.Buffer) *bufio.Scanner {
	if out == nil {
		out = &bytes.Buffer{}
	}

	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return scanner
}

// PreflightTools logs which external tools the current flags require and which
// of them are actually on PATH. Deliberately non-fatal: --skip-amass,
// --skip-nuclei and an omitted --dnsx-list all legitimately make some tools
// unnecessary.
func PreflightTools() {
	resolveToolHome()

	tools := []struct {
		name   string
		needed bool
	}{
		{"subfinder", true},
		{"httpx", true},
		{"amass", !SkipAmass},
		{"dnsx", DnsxList != ""},
		{"nuclei", !SkipNuclei},
		{"gau", true},
		{"katana", true},
		{"subjs", true},
		{"mantra", true},
		{"secretfinder.py", true},
	}

	var present, missing, skipped []string
	for _, t := range tools {
		if !t.needed {
			skipped = append(skipped, t.name)
			continue
		}
		if _, err := exec.LookPath(t.name); err != nil {
			missing = append(missing, t.name)
			continue
		}
		present = append(present, t.name)
	}

	log.Printf("[+] Preflight: %d/%d required tools found: %s", len(present), len(present)+len(missing), strings.Join(present, ", "))
	if len(skipped) > 0 {
		log.Printf("[*] Preflight: not required with the current flags: %s", strings.Join(skipped, ", "))
	}
	if len(missing) > 0 {
		log.Printf("[-] Preflight: MISSING from PATH: %s", strings.Join(missing, ", "))
		log.Printf("[-] Preflight: the phases using those tools will fail. PATH=%s", os.Getenv("PATH"))
	}
}

// cappedBuffer keeps the first limit bytes written to it and counts the rest.
type cappedBuffer struct {
	buf     bytes.Buffer
	limit   int
	dropped int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) <= room {
			c.buf.Write(p)
		} else {
			c.buf.Write(p[:room])
			c.dropped += len(p) - room
		}
	} else {
		c.dropped += len(p)
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	if c.dropped > 0 {
		return fmt.Sprintf("%s ... (%d more bytes suppressed)", c.buf.String(), c.dropped)
	}
	return c.buf.String()
}

func describeStream(s string) string {
	if s = strings.TrimSpace(s); s != "" {
		return s
	}
	return "<empty>"
}
