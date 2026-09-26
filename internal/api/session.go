package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/access"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
)

type principalKey struct{}

func currentUser(r *http.Request) *models.User {
	u, _ := r.Context().Value(principalKey{}).(*models.User)
	return u
}

func sessionUser(c *auth.Claims) (*models.User, error) {
	var u models.User
	err := database.DB.Where("public_id = ? AND auth_version = ?", c.Subject, c.Version).
		Where("EXISTS (SELECT 1 FROM sessions WHERE sessions.id = ? AND sessions.user_id = users.id AND julianday(sessions.expires_at) > julianday(?))", c.ID, time.Now().UTC()).
		First(&u).Error
	if err != nil {
		return nil, err
	}
	if !access.ValidRole(u.Role) {
		return nil, errors.New("invalid account role")
	}
	return &u, nil
}

func issueSession(u *models.User, ttl time.Duration) (string, error) {
	token, err := auth.GenerateTokenWithTTL(u.PublicID, u.AuthVersion, ttl)
	if err != nil {
		return "", err
	}
	c, err := auth.ValidateToken(token)
	if err != nil {
		return "", err
	}
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		// A password/role edit racing login must not issue a usable stale session.
		var live models.User
		if err := tx.Where("id = ? AND auth_version = ?", u.ID, u.AuthVersion).First(&live).Error; err != nil {
			return err
		}
		if !access.ValidRole(live.Role) {
			return errors.New("invalid role")
		}
		if err := tx.Where("julianday(expires_at) <= julianday(?)", time.Now().UTC()).Delete(&models.Session{}).Error; err != nil {
			return err
		}
		return tx.Create(&models.Session{ID: c.ID, UserID: u.ID, ExpiresAt: c.ExpiresAt.Time.UTC()}).Error
	})
	return token, err
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
