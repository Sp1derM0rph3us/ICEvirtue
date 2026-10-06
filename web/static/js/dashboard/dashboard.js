import { setupRedirectDetails, showRedirectDetails } from './redirects.js';
import { mountHistory } from './history.js';
import { closeEditModal, closeSubDashboard, deleteTarget, editSchedule, forceScan, goToPage, goToProfilesPage, hideSeverityTooltip, loadCurrentView, loadHomeOverview, loadNodeAddresses, loadProfilesPage, onHomeProfileChanged, onPageSizeChanged, onProfileChanged, onProfilesPageSizeChanged, onSortChanged, openSeverityTooltip, openSubDashboard, populateMinutes, refreshProfiles, reloadCurrentPage, renderCurrentView, renderProfileRows, resetFilterPills, scheduleLabel, scheduleSeverityTooltip, switchDiscTab, switchSubDashboardTab, switchView, syncSizeSelect, toggleFilter, toggleTheme } from './views.js';
import { api, logout } from './api.js';
import { deleteAllNotifs, loadNotifications, markAllNotifsRead, showToast, toggleNotifPanel } from './notifications.js';
import { mobileLayout, state } from './state.js';
import { readViewState } from './url.js';
import { connectEvents } from './sse.js';

populateMinutes();
document.getElementById('form-add-target')?.addEventListener('submit', async e => {
  e.preventDefault();
  const btn = e.target.querySelector('button');
  const originalText = btn.innerText;
  btn.innerText = "Adding...";
  btn.disabled = true;
  const domain = document.getElementById('input-domain').value;
  const freq = document.getElementById('sched-freq').value;
  let hour = parseInt(document.getElementById('sched-hour').value, 10);
  const min = document.getElementById('sched-min').value;
  const ampm = document.getElementById('sched-ampm').value;
  if (ampm === "PM" && hour < 12) hour += 12;
  if (ampm === "AM" && hour === 12) hour = 0;
  const schedule = `every ${freq} at ${hour.toString().padStart(2, '0')}:${min}`;
  try {
    const res = await api('/api/profiles', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        domain,
        schedule
      })
    });
    if (!res.ok) throw new Error(await res.text());
    const newProfile = await res.json();
    e.target.reset();
    // One refresh rather than three hand-maintained insertions: the table, the
    // picker and the count all come from the server, so they cannot drift.
    await refreshProfiles({
      revealProfileId: newProfile.ID
    });
    showToast({
      cls: 'ok',
      icon: 'check',
      title: 'Profile added',
      sub: domain
    });
  } catch (err) {
    showToast({
      cls: 'crit',
      icon: 'alert',
      title: 'Profile could not be added',
      sub: err.message
    });
  } finally {
    btn.innerText = originalText;
    btn.disabled = false;
  }
});

// Formats Profile.LastScan / Profile.LastScanStatus for the Last Run cell.
// Returns plain text only; the caller assigns it with textContent, since the
// status string originates from the engine rather than from this page.

document.getElementById('form-edit-schedule').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = document.getElementById('btn-save-schedule');
  const originalText = btn.innerText;
  btn.innerText = "Saving...";
  btn.disabled = true;
  const id = document.getElementById('edit-schedule-id').value;
  const freq = document.getElementById('edit-sched-freq').value;
  let hour = parseInt(document.getElementById('edit-sched-hour').value, 10);
  const min = document.getElementById('edit-sched-min').value;
  const ampm = document.getElementById('edit-sched-ampm').value;
  if (ampm === "PM" && hour < 12) hour += 12;
  if (ampm === "AM" && hour === 12) hour = 0;
  const newSchedule = `every ${freq} at ${hour.toString().padStart(2, '0')}:${min}`;
  try {
    const res = await api(`/api/profiles/${id}/schedule`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        schedule: newSchedule
      })
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    const codeEl = document.getElementById(`schedule-text-${id}`);
    if (codeEl) {
      codeEl.dataset.schedule = data.schedule;
      codeEl.title = `Stored schedule: ${data.schedule}`;
      codeEl.textContent = scheduleLabel(data.schedule);
    }
    const profile = state.profileRows.find(p => String(p.ID) === String(id));
    if (profile) profile.Schedule = data.schedule;
    closeEditModal();
    showToast({
      cls: 'ok',
      icon: 'check',
      title: 'Schedule updated',
      sub: profile && profile.Domain ? profile.Domain : scheduleLabel(data.schedule)
    });
  } catch (err) {
    showToast({
      cls: 'crit',
      icon: 'alert',
      title: 'Schedule could not be updated',
      sub: err.message
    });
  } finally {
    btn.innerText = originalText;
    btn.disabled = false;
  }
});
// One delegated listener per generated table, replacing the inline onclick
// handlers those rows used to carry. Registered on the tbody rather than the
// rows, so it survives the innerHTML='' that every re-render does.
const handleProfileAction = e => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const {
    action,
    id,
    domain
  } = btn.dataset;
  if (action === 'scan') forceScan(id);else if (action === 'delete') deleteTarget(id, domain);else if (action === 'edit-schedule') editSchedule(id, domain);
};
['targets-tbody', 'targets-mobile'].forEach(id => document.getElementById(id).addEventListener('click', handleProfileAction));
document.getElementById('view-discoveries').addEventListener('click', e => {
  const btn = e.target.closest('[data-action="open-node"]');
  if (btn) openSubDashboard(btn.dataset.domain, btn.dataset.label);
  const badge = e.target.closest('[data-action="show-severity-summary"], [data-action="show-redirect-summary"]');
  // Let the click's automatic viewport scroll finish before opening the overlay.
  if (badge) requestAnimationFrame(() => openSeverityTooltip(badge));
});

// Delegation survives table redraws. pointerover/out are used because their
// mouseenter/leave counterparts do not bubble from generated badges.
document.getElementById('view-discoveries').addEventListener('pointerover', e => {
  const badge = e.target.closest('[data-action="show-severity-summary"], [data-action="show-redirect-summary"]');
  if (!badge || e.relatedTarget && badge.contains(e.relatedTarget)) return;
  scheduleSeverityTooltip(badge);
});
document.getElementById('view-discoveries').addEventListener('pointerout', e => {
  const badge = e.target.closest('[data-action="show-severity-summary"], [data-action="show-redirect-summary"]');
  if (!badge || e.relatedTarget && badge.contains(e.relatedTarget)) return;
  hideSeverityTooltip();
});
document.getElementById('view-discoveries').addEventListener('focusin', e => {
  const badge = e.target.closest('[data-action="show-severity-summary"], [data-action="show-redirect-summary"]');
  if (badge) openSeverityTooltip(badge);
});
document.getElementById('view-discoveries').addEventListener('focusout', e => {
  if (e.target.closest('[data-action="show-severity-summary"], [data-action="show-redirect-summary"]')) hideSeverityTooltip();
});
document.getElementById('table-subs').addEventListener('scroll', hideSeverityTooltip, {
  passive: true
});
window.addEventListener('scroll', hideSeverityTooltip, {
  passive: true
});
window.addEventListener('resize', hideSeverityTooltip, {
  passive: true
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    hideSeverityTooltip();
    if (!document.getElementById('modal-edit-schedule').classList.contains('hidden')) closeEditModal();
  }
});
mobileLayout.addEventListener('change', () => {
  renderProfileRows();
  if (state.viewState.view === 'findings' && state.viewState.profile) renderCurrentView();
});

// ---- Notifications & toasts ----

// A click anywhere outside the bell closes the panel.
document.addEventListener('click', e => {
  const wrap = document.getElementById('notif-wrap');
  const panel = document.getElementById('notif-panel');
  if (wrap && panel && !panel.classList.contains('hidden') && !wrap.contains(e.target)) {
    panel.classList.add('hidden');
    document.getElementById('notif-bell').setAttribute('aria-expanded', 'false');
  }
});
loadNotifications();
document.addEventListener('DOMContentLoaded', () => {
  // The URL is the source of truth for what to show, so it is read before
  // anything is fetched: a refresh or a shared link lands on the same page.
  readViewState();
  resetFilterPills(state.viewState.filter);
  document.getElementById('select-sort').value = state.viewState.sort;
  document.getElementById('profiles-page-size').value = String(state.viewState.profilesSize);
  syncSizeSelect();
  refreshProfiles().then(() => {
    // A deep link into a node needs its address and its scoped page. The
    // normal Findings activation loads a page itself, so suppress that one
    // only while restoring a node link to avoid two competing requests.
    switchView(state.viewState.view, !state.viewState.node);
    if (state.viewState.view === 'findings' && state.viewState.profile) {
      if (state.viewState.node) {
        loadNodeAddresses();
        loadCurrentView();
      }
    }
  });
});
const actions = {
  'control-0': event => {
    toggleNotifPanel(event);
  },
  'control-1': event => {
    deleteAllNotifs();
  },
  'control-2': event => {
    markAllNotifsRead();
  },
  'control-3': event => {
    switchView('home');
  },
  'control-4': event => {
    switchView('profiles');
  },
  'control-5': event => {
    switchView('findings');
  },
  'control-6': event => {
    toggleTheme();
  },
  'control-7': event => {
    logout();
  },
  'control-8': event => {
    onHomeProfileChanged();
  },
  'control-9': event => {
    switchView('profiles');
  },
  'control-10': event => {
    refreshProfiles().then(() => loadHomeOverview());
  },
  'control-11': event => {
    loadProfilesPage();
  },
  'control-12': event => {
    onProfilesPageSizeChanged();
  },
  'control-13': event => {
    goToProfilesPage(1);
  },
  'control-14': event => {
    goToProfilesPage(state.viewState.profilesPage - 1);
  },
  'control-15': event => {
    goToProfilesPage(state.viewState.profilesPage + 1);
  },
  'control-16': event => {
    goToProfilesPage(state.profilePageMeta.total_pages);
  },
  'control-17': event => {
    onProfileChanged();
  },
  'control-18': event => {
    reloadCurrentPage();
  },
  'control-19': event => {
    switchDiscTab('subs');
  },
  'control-20': event => {
    switchDiscTab('secs');
  },
  'control-21': event => {
    onSortChanged();
  },
  'control-22': event => {
    onPageSizeChanged();
  },
  'control-23': event => {
    toggleFilter('ip');
  },
  'control-24': event => {
    toggleFilter('subdomain');
  },
  'control-25': event => {
    toggleFilter('vuln-critical');
  },
  'control-26': event => {
    toggleFilter('vuln-info');
  },
  'control-27': event => {
    toggleFilter('secrets');
  },
  'control-28': event => {
    toggleFilter('status-2xx-3xx');
  },
  'control-29': event => {
    toggleFilter('status-403');
  },
  'control-30': event => {
    toggleFilter('status-other');
  },
  'control-31': event => {
    toggleFilter('updated');
  },
  'control-32': event => {
    closeSubDashboard();
  },
  'control-33': event => {
    switchSubDashboardTab('vulns');
  },
  'control-34': event => {
    switchSubDashboardTab('dirs');
  },
  'control-35': event => {
    switchSubDashboardTab('secs');
  },
  'control-36': event => {
    goToPage(1);
  },
  'control-37': event => {
    goToPage(state.viewState.page - 1);
  },
  'control-38': event => {
    goToPage(state.viewState.page + 1);
  },
  'control-39': event => {
    goToPage(state.pageMeta.total_pages);
  },
  'control-40': event => {
    closeEditModal();
  },
  
};
document.addEventListener('click', event => {
  const control = event.target.closest('[data-click]');
  if (control) actions[control.dataset.click]?.(event);
});
document.addEventListener('change', event => {
  const control = event.target.closest('[data-change]');
  if (control) actions[control.dataset.change]?.(event);
});
connectEvents();

mountHistory();

setupRedirectDetails();
// The full source -> destination redirect list is now reached only from inside a
// node, where the detail belongs. loadNodeAddresses reveals this button when the
// open node actually has redirects.
document.getElementById('node-redirect-details').addEventListener('click', () => {
  if (state.viewState.node) showRedirectDetails(state.viewState.node);
});
document.getElementById('filter-btn-unknown-directories').addEventListener('click', () => toggleFilter('unknown-directories'));
document.getElementById('directory-assessment-filter').addEventListener('change', e => {
  state.viewState.assessment = e.target.value;
  state.viewState.page = 1;
  loadCurrentView();
});
