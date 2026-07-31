package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// secretLen is the size of a freshly generated signing key.
const secretLen = 64

// minSecretLen rejects a truncated or emptied key file. HMAC with an empty key
// still produces valid signatures, so a zero-length secret would let anyone mint
// their own tokens.
const minSecretLen = 32

// systemSecretDir follows the FHS: /var/lib holds persistent, host-specific
// application state, which is exactly what a self-generated signing key is (as
// opposed to /etc, which is for administrator-authored configuration). A var
// rather than a const so tests need not depend on the real /var permissions.
var systemSecretDir = "/var/lib/icevirtue"

// legacySecretPath is where releases before this change kept the key: relative
// to the working directory. Honoured when it already exists so that upgrading
// does not silently rotate the key and log every session out.
const legacySecretPath = "jwt.secret"

const secretFileName = "jwt.secret"

var jwtSecret []byte

var errNoSecret = errors.New("JWT secret is not initialised; auth.Init must run before the server starts")

// Init loads the JWT signing key, generating and persisting one on first run.
// Call it from main after flag parsing and before the server starts.
//
// This used to be an init() that read and wrote ./jwt.secret, which tied the key
// to the process working directory. As a systemd service with an unwritable
// WorkingDirectory that killed the application during package initialisation,
// before main() ever ran and before any flag could redirect it.
func Init(explicitPath string) error {
	path, err := resolveSecretPath(explicitPath)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) < minSecretLen {
			return fmt.Errorf("JWT secret %s is only %d bytes; delete it so a new one can be generated", path, len(data))
		}
		jwtSecret = data
		log.Printf("[+] Loaded JWT secret from %s", path)
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read JWT secret %s: %w", path, err)
	}

	secret := make([]byte, secretLen)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("failed to generate JWT secret: %w", err)
	}

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create JWT secret directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, secret, 0600); err != nil {
		return fmt.Errorf("failed to write JWT secret %s: %w", path, err)
	}

	jwtSecret = secret
	log.Printf("[+] Generated new JWT secret at %s", path)
	return nil
}

// resolveSecretPath decides where the signing key lives, in priority order:
//
//  1. --jwt-secret, when given.
//  2. An existing ./jwt.secret, so deployments that already have one keep it.
//  3. $STATE_DIRECTORY, which systemd sets from StateDirectory= in the unit and
//     creates with the right ownership for the service user.
//  4. /var/lib/icevirtue, when it is writable — the ordinary service case.
//  5. $XDG_STATE_HOME/icevirtue, defaulting to ~/.local/state/icevirtue, for an
//     unprivileged run that cannot write under /var/lib.
func resolveSecretPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}

	if _, err := os.Stat(legacySecretPath); err == nil {
		abs, absErr := filepath.Abs(legacySecretPath)
		if absErr != nil {
			abs = legacySecretPath
		}
		log.Printf("[*] Using existing JWT secret %s. Move it to %s/%s to stop it depending on the working directory.", abs, systemSecretDir, secretFileName)
		return legacySecretPath, nil
	}

	// systemd documents STATE_DIRECTORY as a colon-separated list; the first
	// entry corresponds to the first StateDirectory= name.
	if stateDir := os.Getenv("STATE_DIRECTORY"); stateDir != "" {
		if first := strings.Split(stateDir, ":")[0]; first != "" {
			return filepath.Join(first, secretFileName), nil
		}
	}

	if err := ensureWritableDir(systemSecretDir); err == nil {
		return filepath.Join(systemSecretDir, secretFileName), nil
	}

	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot decide where to keep the JWT secret: %s is not writable, $XDG_STATE_HOME is unset and $HOME is unusable (%v). Pass --jwt-secret", systemSecretDir, err)
		}
		stateHome = filepath.Join(home, ".local", "state")
	}

	return filepath.Join(stateHome, "icevirtue", secretFileName), nil
}

// ensureWritableDir creates dir and confirms we can actually write inside it.
// os.Stat is not enough: a root-owned /var/lib/icevirtue looks perfectly fine to
// an unprivileged process right up until the write fails.
func ensureWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	probe, err := os.CreateTemp(dir, ".icevirtue-probe-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	probe.Close()

	return os.Remove(name)
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// DefaultSessionTTL is how long a session lasts unless the caller says otherwise.
const DefaultSessionTTL = 24 * time.Hour

func GenerateToken(username string) (string, error) {
	return GenerateTokenWithTTL(username, DefaultSessionTTL)
}

// GenerateTokenWithTTL mints a token with an explicit lifetime.
//
// The explicit form exists so the session length can be configured, and so a test can
// produce an already-expired token. Without it, "an expired session is redirected to
// the login page" could only be tested with a malformed token, which exercises a
// different branch of ValidateToken entirely.
func GenerateTokenWithTTL(username string, ttl time.Duration) (string, error) {
	if len(jwtSecret) < minSecretLen {
		return "", errNoSecret
	}

	now := time.Now()
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ValidateToken(tokenStr string) (*Claims, error) {
	if len(jwtSecret) < minSecretLen {
		return nil, errNoSecret
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims,
		func(token *jwt.Token) (interface{}, error) { return jwtSecret, nil },
		// Pin the algorithm to the one GenerateToken uses, rather than accepting the
		// whole HMAC family. With a single symmetric key this is not exploitable — an
		// attacker who cannot sign HS256 cannot sign HS384 either — but it is the guard
		// that matters the moment anyone reaches for an asymmetric algorithm, where the
		// RS256-to-HS256 confusion attack signs a forged token with the public key.
		//
		// This also replaces the keyfunc's own method check, so there is one place that
		// decides which algorithms are acceptable instead of two.
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		// jwt/v5 does not require exp by default, so a token minted without one would
		// never expire. Nothing mints such a token today; this makes it impossible for
		// anything to start.
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
