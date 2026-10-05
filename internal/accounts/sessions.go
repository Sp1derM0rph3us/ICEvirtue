package accounts

import (
	"errors"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/access"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/auth"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
	"time"
)

type Sessions struct {
	DB     *gorm.DB
	Signer *auth.Signer
}

func (s *Sessions) ByName(name string) (models.User, error) {
	var u models.User
	e := s.DB.Where("username=?", name).First(&u).Error
	return u, e
}
func (s *Sessions) Revoke(id string) error {
	return s.DB.Where("id=?", id).Delete(&models.Session{}).Error
}
func (s *Sessions) ByID(id uint64) (models.User, error) {
	var u models.User
	e := s.DB.First(&u, id).Error
	return u, e
}
func (s *Sessions) User(c *auth.Claims) (*models.User, error) {
	var u models.User
	err := s.DB.Where("public_id = ? AND auth_version = ?", c.Subject, c.Version).
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

func (s *Sessions) Issue(u *models.User, ttl time.Duration) (string, error) {
	token, err := s.Signer.GenerateTokenWithTTL(u.PublicID, u.AuthVersion, ttl)
	if err != nil {
		return "", err
	}
	c, err := s.Signer.ValidateToken(token)
	if err != nil {
		return "", err
	}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
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

func (s *Sessions) List(page int) ([]models.User, int64, int, int, error) {
	var users []models.User
	var total int64
	pages := 1
	e := s.DB.Transaction(func(tx *gorm.DB) error {
		if e := tx.Model(&models.User{}).Count(&total).Error; e != nil {
			return e
		}
		pages = max(1, int((total+49)/50))
		page = min(max(1, page), pages)
		return tx.Select("id, username, role, created_at").Order("username ASC,id ASC").Limit(50).Offset((page - 1) * 50).Find(&users).Error
	})
	return users, total, page, pages, e
}
