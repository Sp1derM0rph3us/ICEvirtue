// Package notifications records per-user, persistent notifications for scan and
// finding events, and pushes a live event to connected clients so the dashboard
// can raise a toast and bump the bell counter without a refetch.
package notifications

import (
	"log"

	"github.com/google/uuid"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/events"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// The four notification kinds the product raises today. They are also sent to
// the client as the event's `kind`, which selects the toast styling and icon.
const (
	ScanStarted  = "scan_started"
	ScanFinished = "scan_finished"
	ScanHalted   = "scan_halted"
	Credentials  = "credentials"
)

// perUserCap bounds how many notifications one user retains. Every scan fans a
// handful of rows out per user, so without a cap the table grows without bound;
// the newest perUserCap are kept and older ones are pruned on each write.
const perUserCap = 200

// Create writes one notification per user (fan-out) and broadcasts a live
// "notification" event carrying the display fields.
//
// It is best-effort: a scan must not fail because a notification could not be
// stored, so errors are logged rather than returned. The live broadcast happens
// regardless of the write, so a connected operator still sees the toast.
func Create(kind, title, body, host string, profileID *uuid.UUID) {
	var userIDs []uint
	if err := database.DB.Model(&models.User{}).Pluck("id", &userIDs).Error; err != nil {
		log.Printf("[-] Notifications: loading users for %q: %v", kind, err)
	}

	if len(userIDs) > 0 {
		rows := make([]models.Notification, 0, len(userIDs))
		for _, uid := range userIDs {
			rows = append(rows, models.Notification{
				UserID: uid, Kind: kind, Title: title, Body: body, Host: host, ProfileID: profileID,
			})
		}
		if err := database.DB.Create(&rows).Error; err != nil {
			log.Printf("[-] Notifications: storing %q for %d user(s): %v", kind, len(userIDs), err)
		} else {
			pruneUsers(userIDs)
		}
	}

	profileStr := ""
	if profileID != nil {
		profileStr = profileID.String()
	}
	// The client does not filter this event by profile — a notification is
	// global to the operator — but the id rides along for future click-through.
	events.Broadcast("notification", profileStr, map[string]interface{}{
		"kind": kind, "title": title, "body": body, "host": host,
	})
}

// pruneUsers deletes each user's notifications beyond the newest perUserCap.
func pruneUsers(userIDs []uint) {
	for _, uid := range userIDs {
		err := database.DB.Exec(`DELETE FROM notifications WHERE user_id = ? AND id NOT IN (
			SELECT id FROM notifications WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?
		)`, uid, uid, perUserCap).Error
		if err != nil {
			log.Printf("[-] Notifications: pruning user %d: %v", uid, err)
		}
	}
}
