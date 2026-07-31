package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func withClaims(ctx context.Context, claims *auth.Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// dummyHash equalises the cost of a login attempt for a username that does not exist.
//
// bcrypt.CompareHashAndPassword against a well-formed cost-10 hash does the same work as
// against a real one, so the response time does not reveal whether the account exists.
// Keep this: it is the reason both failure branches are indistinguishable.
const dummyHash = "$2a$10$w1Dq7OaHxzB5vI/.wQ8/e.cIhA1JvE6cMwI8V/.1S/8gP.G/N./O2"

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// 400, not 401. A malformed body is not an authentication failure, and saying so
		// leaks nothing: the caller already knows what it sent.
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	key := clientKey(r)

	var user models.User
	result := database.DB.Where("username = ?", req.Username).First(&user)

	hashToCompare := dummyHash
	if result.Error == nil {
		hashToCompare = user.PasswordHash
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashToCompare), []byte(req.Password))

	if result.Error != nil || err != nil {
		a.logins.recordFailure(key)
		// Logged for A09. Never log the password; middleware.Logger does not log bodies.
		log.Printf("[-] Failed login for %q from %s", req.Username, key)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString, err := auth.GenerateTokenWithTTL(user.Username, a.cfg.SessionTTL)
	if err != nil {
		log.Printf("[-] Issuing a session for %q: %v", user.Username, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	a.logins.recordSuccess(key)
	http.SetCookie(w, a.authCookie(tokenString, int(a.cfg.SessionTTL.Seconds())))
	respondJSON(w, http.StatusOK, map[string]string{"message": "success"})
}

// handleLogout clears the cookie.
//
// It does not invalidate anything server-side, so a token captured before logout keeps
// working until it expires. Closing that gap needs a per-user "tokens issued before this
// instant are refused" column and a lookup on every request; it is recorded as a
// follow-up rather than done here.
func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, a.authCookie("", -1))
	respondJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}
