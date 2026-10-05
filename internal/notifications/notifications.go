package notifications

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	ScanStarted    = "scan_started"
	ScanFinished   = "scan_finished"
	ScanHalted     = "scan_halted"
	Credentials    = "credentials"
	ProfileDeleted = "profile_deleted"
)
const perUserCap = 200

// Create writes notification rows and their live event in the caller's transaction.
func Create(tx *gorm.DB, kind, title, body, host string, profileID *uuid.UUID) error {
	var ids []uint
	if err := tx.Model(&models.User{}).Pluck("id", &ids).Error; err != nil {
		return err
	}
	for _, id := range ids {
		if err := tx.Create(&models.Notification{UserID: id, Kind: kind, Title: title, Body: body, Host: host, ProfileID: profileID}).Error; err != nil {
			return err
		}
		if err := tx.Exec(`DELETE FROM notifications WHERE user_id=? AND id NOT IN (SELECT id FROM notifications WHERE user_id=? ORDER BY created_at DESC,id DESC LIMIT ?)`, id, id, perUserCap).Error; err != nil {
			return err
		}
	}
	profile := ""
	if profileID != nil {
		profile = profileID.String()
	}
	return events.Append(tx, "notification", profile, map[string]any{"kind": kind, "title": title, "body": body, "host": host})
}
