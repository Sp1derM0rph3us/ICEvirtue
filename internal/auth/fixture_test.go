package auth

import "time"

var testSigner = &Signer{}

func Init(p string) error { return testSigner.Init(p) }
func GenerateTokenWithTTL(s string, v uint64, t time.Duration) (string, error) {
	return testSigner.GenerateTokenWithTTL(s, v, t)
}
func ValidateToken(s string) (*Claims, error) { return testSigner.ValidateToken(s) }
func CSRFToken(c *Claims) string              { return testSigner.CSRFToken(c) }
