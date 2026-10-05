package api

import (
	"context"
	"net/http"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/access"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

type principalKey struct{}

func currentUser(r *http.Request) *models.User {
	u, _ := r.Context().Value(principalKey{}).(*models.User)
	return u
}

func (a *API) sessionUser(c *auth.Claims) (*models.User, error) { return a.sessions.User(c) }
func (a *API) issueSession(u *models.User, ttl time.Duration) (string, error) {
	return a.sessions.Issue(u, ttl)
}

func requirePermission(permission access.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := currentUser(r)
			if u == nil || !access.Allows(u.Role, permission) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Default-deny every authenticated API mutation for viewers, including future
// routes and notification changes. Authentication/logout are separate exceptions.
func requireWritePermission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			requirePermission(access.Write)(next).ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func authenticatedContext(r *http.Request, c *auth.Claims, u *models.User) context.Context {
	return context.WithValue(withClaims(r.Context(), c), principalKey{}, u)
}
