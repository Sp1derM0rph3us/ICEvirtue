// Package accounts owns account mutations, including session invalidation.
package accounts

import (
	"errors"
	"regexp"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/access"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var ErrForbidden = errors.New("this account cannot perform that action")
var ErrConflict = errors.New("the account changed; reload the page and try again")
var ErrLastAdmin = errors.New("the last administrator cannot be deleted or demoted")
var ErrCredentials = errors.New("current password is incorrect")

type ValidationError string

func (e ValidationError) Error() string { return string(e) }

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{2,63}$`)

func ValidateUsername(username string) error {
	if !usernamePattern.MatchString(username) {
		return ValidationError("username must contain 3–64 letters, numbers, dots, underscores, @ or hyphens, beginning with a letter or number")
	}
	return nil
}

func HashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 72 {
		return "", ValidationError("password must contain 12–72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// Authorize again inside the transaction so an already-revoked administrator
// cannot race another administrator's edit with a stale form submission.
func actorInTransaction(tx *gorm.DB, actor *models.User, permission access.Permission) error {
	var current models.User
	if err := tx.Where("id = ? AND auth_version = ?", actor.ID, actor.AuthVersion).First(&current).Error; err != nil {
		return ErrForbidden
	}
	if !access.Allows(current.Role, permission) {
		return ErrForbidden
	}
	return nil
}

func Create(db *gorm.DB, actor *models.User, username, password, role string) error {
	if err := ValidateUsername(username); err != nil {
		return err
	}
	if !access.ValidRole(role) {
		return ValidationError("select a valid role")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := actorInTransaction(tx, actor, access.ManageUsers); err != nil {
			return err
		}
		return tx.Create(&models.User{Username: username, PasswordHash: hash, Role: role}).Error
	})
}

type Edit struct {
	Username, Password, Role, CurrentPassword string
	Version                                   uint64
}

func Update(db *gorm.DB, actor *models.User, id uint, edit Edit, admin bool) error {
	if err := ValidateUsername(edit.Username); err != nil {
		return err
	}
	var hash string
	var err error
	if edit.Password != "" {
		hash, err = HashPassword(edit.Password)
		if err != nil {
			return err
		}
	}
	if admin && !access.ValidRole(edit.Role) {
		return ValidationError("select a valid role")
	}
	return db.Transaction(func(tx *gorm.DB) error {
		permission := access.Write
		if admin {
			permission = access.ManageUsers
		} else if id != actor.ID {
			return ErrForbidden
		}
		if err := actorInTransaction(tx, actor, permission); err != nil {
			return err
		}
		var target models.User
		if err := tx.First(&target, id).Error; err != nil {
			return err
		}
		if target.AuthVersion != edit.Version {
			return ErrConflict
		}
		if !admin && bcrypt.CompareHashAndPassword([]byte(target.PasswordHash), []byte(edit.CurrentPassword)) != nil {
			return ErrCredentials
		}
		if !admin {
			edit.Role = target.Role
		}
		if target.Role == access.Admin && edit.Role != access.Admin {
			if err := anotherAdmin(tx, id); err != nil {
				return err
			}
		}
		updates := map[string]interface{}{"username": edit.Username, "role": edit.Role, "auth_version": gorm.Expr("auth_version + 1")}
		if hash != "" {
			updates["password_hash"] = hash
		}
		if err := tx.Model(&target).Updates(updates).Error; err != nil {
			return err
		}
		return tx.Where("user_id = ?", id).Delete(&models.Session{}).Error
	})
}

func anotherAdmin(tx *gorm.DB, id uint) error {
	var count int64
	if err := tx.Model(&models.User{}).Where("role = ? AND id <> ?", access.Admin, id).Count(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return ErrLastAdmin
	}
	return nil
}

func Delete(db *gorm.DB, actor *models.User, id uint, version uint64) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := actorInTransaction(tx, actor, access.ManageUsers); err != nil {
			return err
		}
		var target models.User
		if err := tx.First(&target, id).Error; err != nil {
			return err
		}
		if target.AuthVersion != version {
			return ErrConflict
		}
		if target.Role == access.Admin {
			if err := anotherAdmin(tx, id); err != nil {
				return err
			}
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.Session{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.Notification{}).Error; err != nil {
			return err
		}
		return tx.Unscoped().Delete(&target).Error
	})
}
