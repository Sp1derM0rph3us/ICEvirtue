// Package appconfig is the shared database authority for application behavior.
package appconfig

import (
	"errors"
	"fmt"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"unicode/utf8"
)

var ErrConflict = errors.New("settings changed; reload before saving")

type ValidationError string

func (e ValidationError) Error() string { return string(e) }
func Defaults() models.ApplicationConfiguration {
	return models.ApplicationConfiguration{ID: 1, Revision: 1, Password: models.PasswordPolicy{Minimum: 8, Maximum: 26}, Scan: models.ScanSettings{SkipDNSX: true, SkipDirectory: true, DNSXWordlists: []string{}, DirectoryWordlists: []string{}}, Tools: models.ToolSettings{WAFTimeoutSeconds: 30, WaymoreResponseLimit: 5000, MaxConcurrentScans: 2}}
}
func Seed(db *gorm.DB) error {
	c := Defaults()
	return db.Clauses(clause.OnConflict{DoNothing: true}).Create(&c).Error
}
func Load(db *gorm.DB) (models.ApplicationConfiguration, error) {
	var c models.ApplicationConfiguration
	err := db.First(&c, 1).Error
	return c, err
}
func ValidatePassword(p models.PasswordPolicy, password string) error {
	if !utf8.ValidString(password) {
		return ValidationError("password must be valid UTF-8")
	}
	if len(password) > 72 {
		return ValidationError("password exceeds bcrypt's 72-byte limit; it will not be truncated")
	}
	n := utf8.RuneCountInString(password)
	if n < p.Minimum || n > p.Maximum {
		return ValidationError(fmt.Sprintf("password must contain %d–%d Unicode characters (at most 72 UTF-8 bytes)", p.Minimum, p.Maximum))
	}
	return nil
}
func CheckPassword(db *gorm.DB, password string) error {
	c, err := Load(db)
	if err != nil {
		return err
	}
	return ValidatePassword(c.Password, password)
}
func Validate(db *gorm.DB, c models.ApplicationConfiguration) error {
	if c.Password.Minimum < 8 || c.Password.Maximum > 72 || c.Password.Minimum > c.Password.Maximum {
		return ValidationError("password limits must satisfy 8 ≤ minimum ≤ maximum ≤ 72")
	}
	if c.Tools.WAFTimeoutSeconds < 1 || c.Tools.WAFTimeoutSeconds > 300 {
		return ValidationError("WAF timeout must be 1–300 seconds")
	}
	if c.Tools.WaymoreResponseLimit < 1 || c.Tools.WaymoreResponseLimit > 50000 {
		return ValidationError("Waymore limit must be 1–50000 responses")
	}
	if c.Tools.MaxConcurrentScans < 1 || c.Tools.MaxConcurrentScans > 4 {
		return ValidationError("concurrent scans must be 1–4")
	}
	for _, s := range []struct {
		ids  []string
		kind string
		skip bool
	}{{c.Scan.DNSXWordlists, "subdomain", c.Scan.SkipDNSX}, {c.Scan.DirectoryWordlists, "directory", c.Scan.SkipDirectory}} {
		if len(s.ids) > 50 || (!s.skip && len(s.ids) == 0) {
			return ValidationError("enabled wordlist stages require 1–50 ready wordlists")
		}
		seen := map[string]bool{}
		for _, id := range s.ids {
			if seen[id] {
				return ValidationError("duplicate wordlist selection")
			}
			seen[id] = true
			var n int64
			if err := db.Model(&models.Wordlist{}).Where("id = ? AND kind = ? AND state = ?", id, s.kind, "ready").Count(&n).Error; err != nil {
				return err
			}
			if n != 1 {
				return ValidationError("selected wordlist is unavailable or has the wrong type")
			}
		}
	}
	return nil
}

// Caller owns the transaction, including authorization. Select(*) writes false values.
func Save(tx *gorm.DB, c *models.ApplicationConfiguration, expected uint64) error {
	if expected == 0 || c.Revision != expected {
		return ErrConflict
	}
	if err := Validate(tx, *c); err != nil {
		return err
	}
	c.Revision++
	result := tx.Model(&models.ApplicationConfiguration{}).Where("id = 1 AND revision = ?", expected).Select("*").Updates(c)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrConflict
	}
	return nil
}
