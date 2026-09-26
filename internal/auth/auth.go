package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/uuid"
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
	// Publish a complete key atomically without overwriting a key created by
	// another starting process. A crash cannot leave an empty signing key.
	file, err := os.CreateTemp(filepath.Dir(path), ".jwt-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(secret); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(file.Name(), path); err != nil {
		if os.IsExist(err) {
			// Another process published first. Read once; a dangling symlink or
			// unreadable path must fail rather than recursively attempting creation.
			existing, readErr := os.ReadFile(path)
			if readErr != nil {
				return fmt.Errorf("reading concurrently created JWT secret: %w", readErr)
			}
			if len(existing) < minSecretLen {
				return fmt.Errorf("JWT secret %s is only %d bytes", path, len(existing))
			}
			jwtSecret = existing
			return nil
		}
		return fmt.Errorf("failed to publish JWT secret %s: %w", path, err)
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

// Claims contain opaque identifiers and security metadata only. Roles and account
// details are loaded from the database for each request, never trusted from a JWT.
type Claims struct {
	Version uint64 `json:"ver"`
	jwt.RegisteredClaims
}

const DefaultSessionTTL = 24 * time.Hour
const MaxSessionTTL = 7 * 24 * time.Hour
const Issuer = "icevirtue"
const Audience = "icevirtue-dashboard"
const TokenType = "icevirtue-session+jwt"

func GenerateTokenWithTTL(subject string, version uint64, ttl time.Duration) (string, error) {
	if len(jwtSecret) < minSecretLen {
		return "", errNoSecret
	}
	if _, err := uuid.Parse(subject); err != nil || subject == uuid.Nil.String() || version == 0 {
		return "", errors.New("invalid session identity")
	}
	if ttl < time.Second || ttl > MaxSessionTTL {
		return "", errors.New("session lifetime must be between one second and seven days")
	}
	now := time.Now().UTC()
	claims := &Claims{Version: version, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: Issuer, Subject: subject, Audience: jwt.ClaimStrings{Audience}, ID: uuid.NewString(),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
	}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["typ"] = TokenType
	return token.SignedString(jwtSecret)
}

func ValidateToken(raw string) (*Claims, error) {
	if len(jwtSecret) < minSecretLen {
		return nil, errNoSecret
	}
	if len(raw) > 4096 {
		return nil, errors.New("token too large")
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Header["typ"] != TokenType {
			return nil, errors.New("invalid token type")
		}
		// No dynamic key selection, remote key URLs, or critical extensions.
		for name := range token.Header {
			if name != "alg" && name != "typ" {
				return nil, errors.New("unsupported token header")
			}
		}
		return jwtSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(),
		jwt.WithIssuer(Issuer), jwt.WithAudience(Audience), jwt.WithIssuedAt(), jwt.WithStrictDecoding())
	if err != nil {
		return nil, err
	}
	if !token.Valid || claims.Version == 0 || claims.IssuedAt == nil || claims.NotBefore == nil || claims.ExpiresAt == nil {
		return nil, errors.New("incomplete session claims")
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return nil, errors.New("invalid subject")
	}
	if _, err := uuid.Parse(claims.ID); err != nil {
		return nil, errors.New("invalid session id")
	}
	if claims.Subject == uuid.Nil.String() || claims.ID == uuid.Nil.String() ||
		!claims.ExpiresAt.After(claims.IssuedAt.Time) || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > MaxSessionTTL ||
		!claims.NotBefore.Equal(claims.IssuedAt.Time) || len(claims.Audience) != 1 {
		return nil, errors.New("invalid session claims")
	}
	return claims, nil
}

// CSRFToken is purpose-separated and tied to one authenticated session. It is
// rendered into server-side forms and compared in constant time on submission.
func CSRFToken(c *Claims) string {
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte("icevirtue-form-csrf:" + c.ID))
	return hex.EncodeToString(mac.Sum(nil))
}
