import { state } from './state.js';
import { loadNotifications, setNotifBadge, toastForNotification } from './notifications.js';
import { loadCurrentView, loadHomeOverview, refreshProfiles, renderNewFindingsBadge } from './views.js';
import { goToLogin } from './api.js';

export function connectEvents() {
  const sse = new EventSource('/api/events');
  sse.onmessage = event => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'stream_reset') {
        state.pendingNewFindings = {};
        loadNotifications();
        refreshProfiles().then(() => {
          loadHomeOverview();
          if (state.viewState.profile) loadCurrentView();
        });
        return;
      }
      if (data.type === "session_revoked") {
        sse.close();
        window.location.replace("/login?reason=session-ended");
        return;
      }
      if (data.type === 'profile_update') {
        refreshProfiles().then(() => {
          if (state.viewState.view === 'home') loadHomeOverview();
        });
        return;
      }
      if (data.type === 'notifications_changed') { loadNotifications(); return; }
      if (data.type === 'notification') {
        // A new server-side notification: raise the transient toast and bump
        // the bell counter. If the panel is open, refetch so the new row
        // (with its id) appears and can be marked read.
        const n = data.data || {};
        loadNotifications();
        toastForNotification(n);
        const panel = document.getElementById('notif-panel');
        if (panel && !panel.classList.contains('hidden')) loadNotifications();
        return;
      }
      if (data.type !== 'discovery_update' || data.profile_id !== state.viewState.profile) return;

      // Count them and say so. This used to schedule a refetch of the entire
      // profile eight seconds after the last event, which meant that during a
      // scan the table was torn down and rebuilt every eight seconds underneath
      // whoever was reading it -- and, with no in-flight guard, could stack a
      // second full run of requests onto an unfinished one.
      for (const [kind, count] of Object.entries(data.data || {})) {
        if (typeof count === 'number' && count > 0) {
          state.pendingNewFindings[kind] = (state.pendingNewFindings[kind] || 0) + count;
          if (kind === 'vulnerabilities') state.severitySummaryCache = new Map();
        }
      }
      renderNewFindingsBadge();
    } catch (e) {
      console.error("Failed to parse SSE event", e);
    }
  };
  sse.onerror = async () => {
    // onerror covers both a dead session and a transient blip, and the two want
    // opposite reactions. readyState tells them apart: anything other than CLOSED
    // means EventSource is still retrying on its own.
    if (sse.readyState !== EventSource.CLOSED) return;
    try {
      const res = await fetch('/api/profiles/index', {
        credentials: 'same-origin'
      });
      if (res.status === 401) goToLogin();
    } catch (e) {
      console.error("SSE Error:", e);
    }
  };
}
