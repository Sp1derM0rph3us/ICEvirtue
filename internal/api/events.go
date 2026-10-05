package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

func (a *API) handleEvents(w http.ResponseWriter, r *http.Request) {
	claims, ok := UserFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", 401)
		return
	}
	first, last, e := a.stream.Bounds()
	if e != nil {
		http.Error(w, "event stream unavailable", 503)
		return
	}
	cursor := last
	if raw := r.Header.Get("Last-Event-ID"); raw != "" {
		cursor, e = strconv.ParseUint(raw, 10, 64)
		if e != nil {
			http.Error(w, "invalid event cursor", 400)
			return
		}
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	send := func(id uint64, data any) bool {
		body, _ := json.Marshal(data)
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, e := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", id, body)
		flusher.Flush()
		return e == nil
	}
	if cursor > last || (cursor < first && first-cursor > 1) {
		if !send(last, map[string]string{"type": "stream_reset"}) {
			return
		}
		cursor = last
	}
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-a.cfg.Shutdown:
			return
		case <-heartbeat.C:
			http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, e := fmt.Fprint(w, ": keep-alive\n\n"); e != nil {
				return
			}
			flusher.Flush()
		case <-tick.C:
			if !time.Now().Before(claims.ExpiresAt.Time) {
				return
			}
			if _, e := a.sessionUser(claims); e != nil {
				send(cursor, map[string]string{"type": "session_revoked"})
				return
			}
			first, last, e := a.stream.Bounds()
			if e != nil {
				return
			}
			if cursor > last || (cursor < first && first-cursor > 1) {
				if !send(last, map[string]string{"type": "stream_reset"}) {
					return
				}
				cursor = last
			}
			rows, e := a.stream.Read(cursor)
			if e != nil {
				return
			}
			for _, row := range rows {
				if !send(row.ID, row) {
					return
				}
				cursor = row.ID
			}
		}
	}
}
