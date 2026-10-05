package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/notifications"
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

type notificationDTO = notifications.Item

// notificationPage bounds one response. The bell shows the recent tail, not the
// whole history; the count of unread is separate so the badge is exact even when
// the list is capped.
const notificationPage = 50

func (a *API) getNotifications(w http.ResponseWriter, r *http.Request) {
	uid, ok := currentUserID(w, r)
	if !ok {
		return
	}

	rows, unread, err := a.inbox.List(uid, notificationPage)
	if err != nil {
		http.Error(w, "failed to list notifications", 500)
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"data": rows, "unread": unread})
}

func (a *API) changeNotification(w http.ResponseWriter, r *http.Request, all, remove bool) {
	uid, ok := currentUserID(w, r)
	if !ok {
		return
	}
	var id uint
	if !all {
		id, ok = notificationID(w, r)
		if !ok {
			return
		}
	}
	n, e := a.inbox.Change(uid, id, remove)
	if e != nil {
		http.Error(w, "failed to update notifications", 500)
		return
	}
	if !all && n == 0 {
		http.Error(w, "notification not found", 404)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (a *API) markNotificationRead(w http.ResponseWriter, r *http.Request) {
	a.changeNotification(w, r, false, false)
}
func (a *API) markAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	a.changeNotification(w, r, true, false)
}
func (a *API) deleteNotification(w http.ResponseWriter, r *http.Request) {
	a.changeNotification(w, r, false, true)
}
func (a *API) deleteAllNotifications(w http.ResponseWriter, r *http.Request) {
	a.changeNotification(w, r, true, true)
}
