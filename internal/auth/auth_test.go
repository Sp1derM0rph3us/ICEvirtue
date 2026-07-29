package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests mutate package globals and the process environment, so none of
// them may call t.Parallel.
func isolate(t *testing.T) {
	t.Helper()

	origSystemDir := systemSecretDir
	origSecret := jwtSecret

	// Point the FHS location at a path no test can create, so each test opts in
	// to the branch it means to exercise.
	systemSecretDir = filepath.Join(t.TempDir(), "locked", "icevirtue")
	jwtSecret = nil

	t.Setenv("STATE_DIRECTORY", "")
	t.Setenv("XDG_STATE_HOME", "")

	// Run from an empty directory so a stray ./jwt.secret cannot be picked up.
	t.Chdir(t.TempDir())

	t.Cleanup(func() {
		systemSecretDir = origSystemDir
		jwtSecret = origSecret
	})
}

func TestResolveSecretPathPrefersExplicitFlag(t *testing.T) {
	isolate(t)

	want := "/somewhere/custom/key.bin"
	got, err := resolveSecretPath(want)
	if err != nil {
		t.Fatalf("resolveSecretPath: %v", err)
	}
	if got != want {
		t.Errorf("resolveSecretPath() = %q, want the --jwt-secret value %q", got, want)
	}
}

// An existing ./jwt.secret must keep being used, otherwise upgrading rotates the
// key and logs every existing session out.
func TestResolveSecretPathHonoursLegacyFileInWorkingDirectory(t *testing.T) {
	isolate(t)

	if err := os.WriteFile(legacySecretPath, make([]byte, secretLen), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := resolveSecretPath("")
	if err != nil {
		t.Fatalf("resolveSecretPath: %v", err)
	}
	if got != legacySecretPath {
		t.Errorf("resolveSecretPath() = %q, want the legacy path %q", got, legacySecretPath)
	}
}

// systemd sets STATE_DIRECTORY from StateDirectory= in the unit, and creates the
// directory with the right ownership for the service user.
func TestResolveSecretPathUsesSystemdStateDirectory(t *testing.T) {
	isolate(t)

	stateDir := t.TempDir()
	t.Setenv("STATE_DIRECTORY", stateDir)

	got, err := resolveSecretPath("")
	if err != nil {
		t.Fatalf("resolveSecretPath: %v", err)
	}
	if want := filepath.Join(stateDir, secretFileName); got != want {
		t.Errorf("resolveSecretPath() = %q, want %q", got, want)
	}
}

func TestResolveSecretPathSplitsColonSeparatedStateDirectory(t *testing.T) {
	isolate(t)

	first := t.TempDir()
	t.Setenv("STATE_DIRECTORY", first+":"+t.TempDir())

	got, err := resolveSecretPath("")
	if err != nil {
		t.Fatalf("resolveSecretPath: %v", err)
	}
	if want := filepath.Join(first, secretFileName); got != want {
		t.Errorf("resolveSecretPath() = %q, want the first entry %q", got, want)
	}
}

func TestResolveSecretPathUsesFHSStateDirWhenWritable(t *testing.T) {
	isolate(t)

	systemSecretDir = filepath.Join(t.TempDir(), "icevirtue")

	got, err := resolveSecretPath("")
	if err != nil {
		t.Fatalf("resolveSecretPath: %v", err)
	}
	if want := filepath.Join(systemSecretDir, secretFileName); got != want {
		t.Errorf("resolveSecretPath() = %q, want %q", got, want)
	}
}

func TestResolveSecretPathFallsBackToXdgStateHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere, so the unwritable-/var/lib branch cannot be exercised")
	}
	isolate(t)

	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	systemSecretDir = filepath.Join(locked, "icevirtue")

	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	got, err := resolveSecretPath("")
	if err != nil {
		t.Fatalf("resolveSecretPath: %v", err)
	}
	if want := filepath.Join(stateHome, "icevirtue", secretFileName); got != want {
		t.Errorf("resolveSecretPath() = %q, want %q", got, want)
	}
}

func TestResolveSecretPathDefaultsToLocalStateUnderHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere, so the unwritable-/var/lib branch cannot be exercised")
	}
	isolate(t)

	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	systemSecretDir = filepath.Join(locked, "icevirtue")

	home := t.TempDir()
	t.Setenv("HOME", home)

	got, err := resolveSecretPath("")
	if err != nil {
		t.Fatalf("resolveSecretPath: %v", err)
	}
	if want := filepath.Join(home, ".local", "state", "icevirtue", secretFileName); got != want {
		t.Errorf("resolveSecretPath() = %q, want the XDG default %q", got, want)
	}
}

// The whole point of the change: the key must not depend on the working
// directory, because a systemd service can have an unwritable one.
func TestInitWorksFromAnUnwritableWorkingDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere, so an unwritable working directory cannot be simulated")
	}
	isolate(t)

	cwd := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(cwd, 0500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Chdir(cwd)

	stateDir := t.TempDir()
	t.Setenv("STATE_DIRECTORY", stateDir)

	if err := Init(""); err != nil {
		t.Fatalf("Init: %v", err)
	}

	path := filepath.Join(stateDir, secretFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected the key at %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("key permissions = %v, want 0600", got)
	}
	if info.Size() != secretLen {
		t.Errorf("key size = %d, want %d", info.Size(), secretLen)
	}
}

func TestInitReusesAnExistingKey(t *testing.T) {
	isolate(t)

	stateDir := t.TempDir()
	t.Setenv("STATE_DIRECTORY", stateDir)

	if err := Init(""); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	first := string(jwtSecret)

	jwtSecret = nil
	if err := Init(""); err != nil {
		t.Fatalf("second Init: %v", err)
	}
	if string(jwtSecret) != first {
		t.Error("Init generated a new key instead of reusing the persisted one, which would invalidate every session on restart")
	}
}

// An empty or truncated key file is dangerous rather than merely broken: HMAC
// with an empty key still verifies, so anyone could mint their own tokens.
func TestInitRejectsATruncatedKeyFile(t *testing.T) {
	isolate(t)

	stateDir := t.TempDir()
	t.Setenv("STATE_DIRECTORY", stateDir)
	if err := os.WriteFile(filepath.Join(stateDir, secretFileName), []byte("short"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := Init("")
	if err == nil {
		t.Fatal("expected Init to reject a 5-byte key")
	}
	if !strings.Contains(err.Error(), "only 5 bytes") {
		t.Errorf("error should say how short the key is, got: %v", err)
	}
}

func TestTokensAreRejectedBeforeInit(t *testing.T) {
	isolate(t)

	if _, err := GenerateToken("someone"); err == nil {
		t.Error("GenerateToken must fail before Init rather than sign with an empty key")
	}
	if _, err := ValidateToken("anything"); err == nil {
		t.Error("ValidateToken must fail before Init rather than accept an unsigned token")
	}
}

func TestGenerateAndValidateRoundTrip(t *testing.T) {
	isolate(t)

	t.Setenv("STATE_DIRECTORY", t.TempDir())
	if err := Init(""); err != nil {
		t.Fatalf("Init: %v", err)
	}

	token, err := GenerateToken("netrunner")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	claims, err := ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Username != "netrunner" {
		t.Errorf("Username = %q, want %q", claims.Username, "netrunner")
	}
}

// A token signed with a different key must not validate; this is what would
// break silently if the secret were ever allowed to be empty.
func TestValidateRejectsTokenFromADifferentKey(t *testing.T) {
	isolate(t)

	t.Setenv("STATE_DIRECTORY", t.TempDir())
	if err := Init(""); err != nil {
		t.Fatalf("Init: %v", err)
	}
	token, err := GenerateToken("netrunner")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// Re-initialise against a fresh state directory to get a different key.
	jwtSecret = nil
	t.Setenv("STATE_DIRECTORY", t.TempDir())
	if err := Init(""); err != nil {
		t.Fatalf("second Init: %v", err)
	}

	if _, err := ValidateToken(token); err == nil {
		t.Error("a token signed with the previous key must not validate")
	}
}
