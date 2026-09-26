package api

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/database"
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

// The notification endpoints are scoped to the authenticated user. Every query
// carries `user_id = ?`, so one operator can never read, clear, or mark another
// operator's notifications — the same value that Create fanned a row out to.

// currentUserID uses the account already validated by the session middleware.
func currentUserID(w http.ResponseWriter, r *http.Request) (uint, bool) {
	user := currentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return 0, false
	}
	return user.ID, true
}

// notificationID reads and validates the {id} path parameter.
func notificationID(w http.ResponseWriter, r *http.Request) (uint, bool) {
	n, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid notification id", http.StatusBadRequest)
		return 0, false
	}
	return uint(n), true
}

type notificationDTO struct {
	ID        uint      `json:"id"`
	Kind      string    `json:"kind"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Host      string    `json:"host"`
	Read      bool      `json:"read"`
	CreatedAt time.Time `json:"created_at"`
}

// notificationPage bounds one response. The bell shows the recent tail, not the
// whole history; the count of unread is separate so the badge is exact even when
// the list is capped.
const notificationPage = 50

func getNotifications(w http.ResponseWriter, r *http.Request) {
	uid, ok := currentUserID(w, r)
	if !ok {
		return
	}

	var rows []notificationDTO
	if err := database.DB.Model(&models.Notification{}).
		Where("user_id = ?", uid).
		Order("created_at DESC, id DESC").
		Limit(notificationPage).
		Scan(&rows).Error; err != nil {
		log.Printf("[-] Listing notifications: %v", err)
		http.Error(w, "failed to list notifications", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []notificationDTO{}
	}
	for i := range rows {
		rows[i].CreatedAt = rows[i].CreatedAt.UTC()
	}

	var unread int64
	if err := database.DB.Model(&models.Notification{}).
		Where("user_id = ? AND read = ?", uid, false).Count(&unread).Error; err != nil {
		log.Printf("[-] Counting unread notifications: %v", err)
		http.Error(w, "failed to list notifications", http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"data": rows, "unread": unread})
}

// markNotificationRead marks one notification read (the click-to-read action).
func markNotificationRead(w http.ResponseWriter, r *http.Request) {
	uid, ok := currentUserID(w, r)
	if !ok {
		return
	}
	id, ok := notificationID(w, r)
	if !ok {
		return
	}
	res := database.DB.Model(&models.Notification{}).
		Where("id = ? AND user_id = ?", id, uid).
		Update("read", true)
	if res.Error != nil {
		log.Printf("[-] Marking notification %d read: %v", id, res.Error)
		http.Error(w, "failed to update notification", http.StatusInternalServerError)
		return
	}
	if res.RowsAffected == 0 {
		http.Error(w, "notification not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// markAllNotificationsRead clears the unread state for the whole inbox.
func markAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	uid, ok := currentUserID(w, r)
	if !ok {
		return
	}
	if err := database.DB.Model(&models.Notification{}).
		Where("user_id = ? AND read = ?", uid, false).
		Update("read", true).Error; err != nil {
		log.Printf("[-] Marking all notifications read: %v", err)
		http.Error(w, "failed to update notifications", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteNotification removes one notification (the per-item dismiss).
func deleteNotification(w http.ResponseWriter, r *http.Request) {
	uid, ok := currentUserID(w, r)
	if !ok {
		return
	}
	id, ok := notificationID(w, r)
	if !ok {
		return
	}
	res := database.DB.Where("id = ? AND user_id = ?", id, uid).Delete(&models.Notification{})
	if res.Error != nil {
		log.Printf("[-] Deleting notification %d: %v", id, res.Error)
		http.Error(w, "failed to delete notification", http.StatusInternalServerError)
		return
	}
	if res.RowsAffected == 0 {
		http.Error(w, "notification not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteAllNotifications clears the whole inbox — the panel's "Delete all".
//
// Notifications are hard-deleted (the model carries no DeletedAt), so this is a
// real DELETE, not a soft one: a cleared inbox is gone, not merely hidden.
func deleteAllNotifications(w http.ResponseWriter, r *http.Request) {
	uid, ok := currentUserID(w, r)
	if !ok {
		return
	}
	if err := database.DB.Where("user_id = ?", uid).Delete(&models.Notification{}).Error; err != nil {
		log.Printf("[-] Deleting all notifications: %v", err)
		http.Error(w, "failed to delete notifications", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
