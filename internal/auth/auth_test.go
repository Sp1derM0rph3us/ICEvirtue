package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	if _, err := GenerateTokenWithTTL(testSubject, 1, time.Hour); err == nil {
		t.Fatal("signed without a key")
	}
	if _, err := ValidateToken("anything"); err == nil {
		t.Fatal("validated without a key")
	}
}

const testSubject = "142dc1ed-c208-4b90-b985-ab588e32e6e1"

func tokenFixture(t *testing.T) (string, *Claims) {
	t.Helper()
	isolate(t)
	t.Setenv("STATE_DIRECTORY", t.TempDir())
	if err := Init(""); err != nil {
		t.Fatal(err)
	}
	raw, err := GenerateTokenWithTTL(testSubject, 3, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ValidateToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, c
}

func TestGenerateAndValidateRoundTrip(t *testing.T) {
	raw, c := tokenFixture(t)
	if c.Subject != testSubject || c.Version != 3 || c.ID == "" {
		t.Fatalf("incorrect claims: %+v", c)
	}
	if strings.Contains(raw, "netrunner") {
		t.Fatal("PII in token")
	}
	if c.Issuer != Issuer || len(c.Audience) != 1 || c.Audience[0] != Audience {
		t.Fatal("missing issuer/audience")
	}
	another, err := GenerateTokenWithTTL(testSubject, 3, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := ValidateToken(another)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == c2.ID {
		t.Fatal("reused session id")
	}
}

func TestJWTRejectsInvalidClaimsAndHeaders(t *testing.T) {
	_, base := tokenFixture(t)
	cases := map[string]func(*Claims, *jwt.Token){
		"issuer":             func(c *Claims, _ *jwt.Token) { c.Issuer = "other" },
		"audience":           func(c *Claims, _ *jwt.Token) { c.Audience = jwt.ClaimStrings{"other"} },
		"missing audience":   func(c *Claims, _ *jwt.Token) { c.Audience = nil },
		"multiple audiences": func(c *Claims, _ *jwt.Token) { c.Audience = jwt.ClaimStrings{Audience, "other"} },
		"subject":            func(c *Claims, _ *jwt.Token) { c.Subject = "username" },
		"session id":         func(c *Claims, _ *jwt.Token) { c.ID = "" },
		"version":            func(c *Claims, _ *jwt.Token) { c.Version = 0 },
		"no expiry":          func(c *Claims, _ *jwt.Token) { c.ExpiresAt = nil },
		"no issued at":       func(c *Claims, _ *jwt.Token) { c.IssuedAt = nil },
		"no not before":      func(c *Claims, _ *jwt.Token) { c.NotBefore = nil },
		"future issued at":   func(c *Claims, _ *jwt.Token) { c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour)) },
		"future not before":  func(c *Claims, _ *jwt.Token) { c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour)) },
		"expired":            func(c *Claims, _ *jwt.Token) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute)) },
		"excessive lifetime": func(c *Claims, _ *jwt.Token) {
			c.ExpiresAt = jwt.NewNumericDate(c.IssuedAt.Add(MaxSessionTTL + time.Hour))
		},
		"type":            func(_ *Claims, t *jwt.Token) { t.Header["typ"] = "JWT" },
		"key URL":         func(_ *Claims, t *jwt.Token) { t.Header["jku"] = "https://attacker.invalid/key" },
		"critical header": func(_ *Claims, t *jwt.Token) { t.Header["crit"] = []string{"bad"} },
		"HS384":           func(_ *Claims, t *jwt.Token) { t.Method = jwt.SigningMethodHS384; t.Header["alg"] = "HS384" },
		"HS512":           func(_ *Claims, t *jwt.Token) { t.Method = jwt.SigningMethodHS512; t.Header["alg"] = "HS512" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := *base
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, &c)
			token.Header["typ"] = TokenType
			mutate(&c, token)
			raw, err := token.SignedString(jwtSecret)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateToken(raw); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
}

func TestValidateRejectsTokenFromADifferentKey(t *testing.T) {
	raw, _ := tokenFixture(t)
	jwtSecret = []byte(strings.Repeat("different", 8))
	if _, err := ValidateToken(raw); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestTokenTamperingAndUnsigned(t *testing.T) {
	raw, c := tokenFixture(t)
	parts := strings.Split(raw, ".")
	parts[2] = "AAAA"
	if _, err := ValidateToken(strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered signature accepted")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, c)
	token.Header["typ"] = TokenType
	unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateToken(unsigned); err == nil {
		t.Fatal("unsigned token accepted")
	}
}

func TestGenerateTokenWithTTL(t *testing.T) {
	tokenFixture(t)
	for _, ttl := range []time.Duration{-time.Minute, 0, MaxSessionTTL + time.Second} {
		if _, err := GenerateTokenWithTTL(testSubject, 1, ttl); err == nil {
			t.Fatalf("accepted TTL %v", ttl)
		}
	}
}

func TestInitRejectsDanglingKeySymlink(t *testing.T) {
	isolate(t)
	path := filepath.Join(t.TempDir(), "jwt.secret")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), path); err != nil {
		t.Fatal(err)
	}
	if err := Init(path); err == nil {
		t.Fatal("dangling key symlink accepted")
	}
}
