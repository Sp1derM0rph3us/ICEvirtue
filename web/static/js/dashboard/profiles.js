import { CAN_WRITE, PAGE_SIZES, mobileLayout, state } from './state.js';
import { api, apiJSON } from './api.js';
import { writeViewState } from './url.js';
import { showToast } from './notifications.js';
import { onProfileChanged } from "./navigation.js";
import { esc } from "./format.js";
// api is the only way this page talks to the server.
//
// It carries the timeout that did not exist before, and it names what failed. The
// previous code surfaced every failure as the same fixed string, with the actual
// status only reaching console.error.
export function populateMinutes() {
  const selects = ['sched-min', 'edit-sched-min'];
  selects.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = '';
    for (let i = 0; i < 60; i++) {
      const val = i.toString().padStart(2, '0');
      const opt = document.createElement('option');
      opt.value = val;
      opt.innerText = val;
      el.appendChild(opt);
    }
  });
}
export
// Formats Profile.LastScan / Profile.LastScanStatus for the Last Run cell.
// Returns plain text only; the caller assigns it with textContent, since the
// status string originates from the engine rather than from this page.
function lastRunText(p) {
  const status = p.LastScanStatus || '';
  if (!status) return 'never run';
  const stamp = p.LastScan ? new Date(p.LastScan) : null;
  if (!stamp || isNaN(stamp) || stamp.getFullYear() < 2000) return status;
  const mins = Math.floor((Date.now() - stamp.getTime()) / 60000);
  let ago;
  if (mins < 1) ago = 'just now';else if (mins < 60) ago = `${mins}m ago`;else if (mins < 1440) ago = `${Math.floor(mins / 60)}h ago`;else ago = `${Math.floor(mins / 1440)}d ago`;
  return `${status} · ${ago}`;
}

// The stored value is the scheduler's source of truth. Only its label is
// prettified; an @every interval has no fixed time of day to display.
export function scheduleLabel(raw) {
  const value = String(raw || '').trim();
  const calendar = /^every (day|week|month|year) at (\d{1,2}):(\d{2})$/i.exec(value);
  if (calendar) return `Every ${calendar[1].toLowerCase()} at ${calendar[2].padStart(2, '0')}:${calendar[3]}`;
  const interval = /^@every\s+(\d+)(h|m|s)$/i.exec(value);
  if (interval) {
    const n = Number(interval[1]);
    const unit = interval[2].toLowerCase();
    if (unit === 'h' && n % 24 === 0) {
      const days = n / 24;
      return `Every ${days} ${days === 1 ? 'day' : 'days'} (interval)`;
    }
    const unitName = unit === 'h' ? 'hour' : unit === 'm' ? 'minute' : 'second';
    return `Every ${n} ${unitName}${n === 1 ? '' : 's'} (interval)`;
  }
  return value || 'Not scheduled';
}

// Builds one row of the targets table and returns it. Both the add-target
// handler and refreshProfiles go through here so the markup lives in one place.
export function buildTargetRow(p, animate) {
  const tr = document.createElement('tr');
  tr.id = `row-profile-${p.ID}`;
  tr.className = "group" + (animate ? " animate-fade-in" : "");
  const statusHtml = p.IsScanning ? `<span class="chroma-status"><span class="chroma-status-dot"></span>Scanning</span>` : `<span class="chroma-status chroma-status--idle">${p.IsQueued ? 'Queued' : 'Idle'}</span>`;
  const id = esc(p.ID);
  const shortID = esc(String(p.ID).slice(0, 6));
  const domain = esc(p.Domain);
  const schedule = esc(String(p.Schedule || ''));
  const scheduleText = esc(scheduleLabel(p.Schedule));

  // The row's controls carry their arguments in data-* attributes and are
  // dispatched by one delegated listener per table. Interpolating a domain
  // into onclick="fn('...')" would place untrusted text inside a JS string
  // literal, a context HTML escaping cannot make safe.
  let actionHtml = `<button data-run-history="${id}" class="chroma-button-secondary">Run history</button>`;
  if (!p.IsScanning && !p.IsQueued) {
    actionHtml += `<button data-action="scan" data-id="${id}" class="chroma-button-secondary">Run scan</button> `;
  }
  actionHtml += `<button data-action="delete" data-id="${id}" data-domain="${domain}" class="chroma-button-secondary chroma-button-danger">Delete</button>`;
  const halted = (p.LastScanStatus || '').startsWith('halted');
  const lastRunClass = halted ? "text-rose-500/80" : "text-slate-500";
  tr.innerHTML = `
                <td class="p-5 text-slate-700 font-mono font-bold text-xs uppercase tracking-tight"><span title="${id}" aria-label="Profile ID ${id}">${shortID}</span></td>
                <td class="p-5 font-mono font-bold text-slate-200 text-sm tracking-tight">${domain}</td>
                <td class="p-5 text-slate-500">
                    <div class="chroma-profile-schedule">
                    <span id="schedule-text-${id}" data-schedule="${schedule}" title="Stored schedule: ${schedule}" class="chroma-schedule-label">${scheduleText}</span>
                    <button data-action="edit-schedule" data-id="${id}" data-domain="${domain}" class="chroma-button-secondary chroma-edit-schedule" aria-label="Edit schedule for ${domain}" title="Edit schedule">
                        <svg class="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"></path></svg>
                    </button>
                    </div>
                </td>
                <td class="p-5">${statusHtml}</td>
                <td class="p-5 font-mono text-xs tracking-tighter ${lastRunClass}" id="last-run-${id}"></td>
                <td class="p-5"><div class="flex flex-wrap gap-2 justify-end">${actionHtml}</div></td>
            `;

  // textContent, not innerHTML: the status comes from the engine.
  tr.querySelector(`#last-run-${id}`).textContent = lastRunText(p);
  if (!CAN_WRITE) tr.querySelectorAll('[data-action]').forEach(el => el.remove());
  return tr;
}
export function buildTargetCard(p) {
  const li = document.createElement('li');
  const id = esc(p.ID);
  const domain = esc(p.Domain);
  const schedule = esc(String(p.Schedule || ''));
  li.id = `row-profile-${p.ID}`;
  li.className = 'chroma-mobile-card';
  li.innerHTML = `<h3>${domain}</h3>
                <dl><dt>Schedule</dt><dd><span id="schedule-text-${id}" data-schedule="${schedule}" title="Stored schedule: ${schedule}">${esc(scheduleLabel(p.Schedule))}</span></dd>
                    <dt>Status</dt><dd>${p.IsScanning ? 'Scanning' : p.IsQueued ? 'Queued' : 'Idle'}</dd>
                    <dt>Last run</dt><dd class="${(p.LastScanStatus || '').startsWith('halted') ? 'text-rose-500' : ''}"></dd></dl>
                <button data-run-history="${id}" class="chroma-button-secondary">Run history</button><div class="chroma-mobile-actions">
                    <button type="button" data-action="edit-schedule" data-id="${id}" data-domain="${domain}" class="chroma-button-secondary">Edit schedule</button>
                    ${p.IsScanning || p.IsQueued ? '' : `<button type="button" data-action="scan" data-id="${id}" class="chroma-button-secondary">Run scan</button>`}
                    <button type="button" data-action="delete" data-id="${id}" data-domain="${domain}" class="chroma-button-secondary chroma-button-danger">Delete</button>
                </div>`;
  li.querySelector('dl dd:last-child').textContent = lastRunText(p);
  if (!CAN_WRITE) li.querySelector('.chroma-mobile-actions').remove();
  return li;
}
export function renderProfileRows() {
  const tbody = document.getElementById('targets-tbody');
  const mobile = document.getElementById('targets-mobile');
  tbody.replaceChildren();
  mobile.replaceChildren();
  const frag = document.createDocumentFragment();
  state.profileRows.forEach(p => frag.appendChild(mobileLayout.matches ? buildTargetCard(p) : buildTargetRow(p, false)));
  (mobileLayout.matches ? mobile : tbody).appendChild(frag);
  document.getElementById('targets-empty').classList.toggle('hidden', state.profileRows.length > 0 || state.profilePageMeta.total_rows > 0 || state.profilePageError);
}
export function renderProfilesPager() {
  const pager = document.getElementById('profiles-pager');
  const showing = state.profilePageMeta.total_rows > 0 && !state.profilePageError;
  pager.classList.toggle('hidden', !showing);
  pager.classList.toggle('flex', showing);
  document.getElementById('profiles-page-error').classList.toggle('hidden', !state.profilePageError);
  document.getElementById('profiles-page-size').value = String(state.viewState.profilesSize);
  document.getElementById('profiles-page-size').disabled = state.profilePageLoading;
  if (!showing) return;
  const from = (state.profilePageMeta.page - 1) * state.profilePageMeta.size + 1;
  const to = Math.min(state.profilePageMeta.page * state.profilePageMeta.size, state.profilePageMeta.total_rows);
  document.getElementById('profiles-pager-summary').textContent = `${from}–${to} of ${state.profilePageMeta.total_rows}`;
  document.getElementById('profiles-pager-position').textContent = `Page ${state.profilePageMeta.page} / ${state.profilePageMeta.total_pages}`;
  const atFirst = state.profilePageMeta.page <= 1;
  const atLast = state.profilePageMeta.page >= state.profilePageMeta.total_pages;
  for (const [action, disabled] of Object.entries({
    first: atFirst,
    prev: atFirst,
    next: atLast,
    last: atLast
  })) {
    pager.querySelector(`[data-profile-pager="${action}"]`).disabled = state.profilePageLoading || disabled;
  }
}

// The table uses one page; the separate, compact index keeps every profile
// available in Home and Findings even when this table has many pages.
export async function loadProfilesPage() {
  const request = ++state.profilePageRequest;
  state.profilePageLoading = true;
  state.profilePageError = false;
  renderProfilesPager();
  writeViewState();
  try {
    const params = new URLSearchParams({
      page: String(state.viewState.profilesPage),
      size: String(state.viewState.profilesSize),
      sort: 'domain-asc'
    });
    const table = await apiJSON(`/api/profiles?${params}`);
    if (request !== state.profilePageRequest) return;
    state.profileRows = table.data || [];
    state.profilePageMeta = table.page;
    state.viewState.profilesPage = state.profilePageMeta.page;
    state.viewState.profilesSize = state.profilePageMeta.size;
    writeViewState();
    renderProfileRows();
    const count = state.profilePageMeta.total_rows;
    document.getElementById('target-count').textContent = `${count} ${count === 1 ? 'profile' : 'profiles'}`;
  } catch (err) {
    if (request !== state.profilePageRequest) return;
    console.error('Error loading profiles page:', err);
    state.profileRows = [];
    state.profilePageError = true;
    renderProfileRows();
  } finally {
    if (request === state.profilePageRequest) {
      state.profilePageLoading = false;
      renderProfilesPager();
    }
  }
}
export async function refreshProfileIndex() {
  try {
    const options = await apiJSON('/api/profiles/index');
    const select = document.getElementById('select-profile');
    select.innerHTML = '';
    (options || []).forEach(o => {
      const opt = document.createElement('option');
      opt.value = o.id;
      // textContent, not innerText assignment through a string: the domain is
      // validated on create but this keeps the escaping story uniform.
      opt.textContent = o.domain;
      select.appendChild(opt);
    });
    if (state.viewState.profile) select.value = state.viewState.profile;
    const homeSelect = document.getElementById('select-home-profile');
    homeSelect.replaceChildren();
    (options || []).forEach(o => {
      const opt = document.createElement('option');
      opt.value = o.id;
      opt.textContent = o.domain;
      homeSelect.appendChild(opt);
    });
    if (!options || !options.some(o => o.id === state.viewState.homeProfile)) {
      state.viewState.homeProfile = options && options.length ? options[0].id : null;
    }
    homeSelect.disabled = !state.viewState.homeProfile;
    if (state.viewState.homeProfile) homeSelect.value = state.viewState.homeProfile;
    writeViewState();
    state.profileIndexReady = true;
    return options || [];
  } catch (err) {
    console.error('Error refreshing profile index:', err);
    state.profileIndexReady = false;
    return null;
  }
}
export async function refreshProfiles({
  revealProfileId = null
} = {}) {
  if (revealProfileId) {
    const options = await refreshProfileIndex();
    if (options) {
      const index = options.findIndex(option => option.id === String(revealProfileId));
      if (index >= 0) state.viewState.profilesPage = Math.floor(index / state.viewState.profilesSize) + 1;
    }
    await loadProfilesPage();
  } else {
    await Promise.all([loadProfilesPage(), refreshProfileIndex()]);
  }
}
export function onProfilesPageSizeChanged() {
  const size = Number(document.getElementById('profiles-page-size').value);
  if (!PAGE_SIZES.includes(size)) return;
  const firstRow = (state.profilePageMeta.page - 1) * state.profilePageMeta.size;
  state.viewState.profilesSize = size;
  state.viewState.profilesPage = Math.floor(firstRow / size) + 1;
  loadProfilesPage();
}
export function goToProfilesPage(page) {
  const target = Math.min(Math.max(page, 1), Math.max(state.profilePageMeta.total_pages, 1));
  if (target === state.viewState.profilesPage) return;
  state.viewState.profilesPage = target;
  loadProfilesPage();
}
// Deletion is fire-and-confirm-by-notification: the browser confirm()/alert()
// dialogs were replaced by the app's own feedback path. Success is announced by
// the server's "profile deleted" notification over SSE (toast + bell counter),
// exactly as forceScan relies on the engine's "scan started" notification, so
// nothing is shown here on success. Only the failure toast is raised locally.
export async function deleteTarget(id, domain) {
  try {
    const res = await api(`/api/profiles/${id}`, {
      method: 'DELETE'
    });
    if (!res.ok) throw new Error(await res.text());
    state.profileRows = state.profileRows.filter(p => String(p.ID) !== String(id));
    renderProfileRows();
    const select = document.getElementById('select-profile');
    const wasSelected = state.viewState.profile === id;
    Array.from(select.options).forEach(opt => {
      if (opt.value == id) opt.remove();
    });
    if (wasSelected) {
      select.value = select.options.length > 0 ? select.options[0].value : "";
      onProfileChanged();
    }
    await refreshProfiles();
  } catch (err) {
    showToast({
      cls: 'crit',
      icon: 'alert',
      title: 'Profile could not be deleted',
      sub: err.message
    });
  }
}
export function editSchedule(id, domain) {
  state.scheduleTrigger = document.activeElement;
  document.getElementById('edit-schedule-id').value = id;
  document.getElementById('edit-schedule-domain').innerText = `Target: ${domain}`;
  document.getElementById('form-edit-schedule').reset();
  const scheduleText = document.getElementById(`schedule-text-${id}`).dataset.schedule;
  const regex = /^every (day|week|month|year) at (\d{1,2}):(\d{2})$/i;
  const match = scheduleText.match(regex);
  document.getElementById('edit-schedule-hint').classList.toggle('hidden', !!match);
  if (match) {
    const freq = match[1].toLowerCase();
    let hour24 = parseInt(match[2], 10);
    const min = match[3];
    let ampm = "AM",
      hour12 = hour24;
    if (hour24 === 0) {
      hour12 = 12;
      ampm = "AM";
    } else if (hour24 === 12) {
      hour12 = 12;
      ampm = "PM";
    } else if (hour24 > 12) {
      hour12 = hour24 - 12;
      ampm = "PM";
    }
    document.getElementById('edit-sched-freq').value = freq;
    document.getElementById('edit-sched-hour').value = hour12.toString().padStart(2, '0');
    document.getElementById('edit-sched-min').value = min;
    document.getElementById('edit-sched-ampm').value = ampm;
  }
  const modal = document.getElementById('modal-edit-schedule');
  modal.classList.remove('hidden');
  modal.classList.add('flex');
  document.getElementById('edit-sched-freq').focus();
}
export function closeEditModal() {
  const modal = document.getElementById('modal-edit-schedule');
  modal.classList.add('hidden');
  modal.classList.remove('flex');
  document.getElementById('form-edit-schedule').reset();
  if (state.scheduleTrigger && state.scheduleTrigger.isConnected) state.scheduleTrigger.focus();
  state.scheduleTrigger = null;
}
export async function forceScan(id) {
  try {
    await api(`/api/profiles/${id}/scan`, {
      method: 'POST'
    });
    // Success is announced by the engine's "scan started" notification over
    // SSE (toast + bell counter), so nothing is shown here.
  } catch (err) {
    showToast({
      cls: 'crit',
      icon: 'alert',
      title: 'Scan could not start',
      sub: err.message
    });
  }
}

// resetFilterPills paints every pill inactive, then highlights the active one.
// Both this and the filter reset elsewhere go through PILL_* so the two can
// never drift apart again.
