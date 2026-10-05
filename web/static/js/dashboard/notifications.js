import { CAN_WRITE, NOTIF_ICONS, NOTIF_STYLE, state } from './state.js';
import { api, apiJSON } from './api.js';

export function notifRelTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
export function setNotifBadge(n) {
  state.notifUnread = Math.max(0, n);
  const badge = document.getElementById('notif-badge');
  badge.textContent = state.notifUnread > 99 ? '99+' : String(state.notifUnread);
  badge.classList.toggle('hidden', state.notifUnread === 0);
}
export function renderNotifPanel() {
  const list = document.getElementById('notif-list');
  list.replaceChildren();
  document.getElementById('notif-empty').classList.toggle('hidden', state.notifItems.length > 0);
  document.getElementById('notif-markread')?.parentElement.classList.toggle('hidden', state.notifItems.length === 0);
  document.getElementById('notif-count').textContent = state.notifUnread ? state.notifUnread + ' unread' : '';
  for (const n of state.notifItems) {
    const style = NOTIF_STYLE[n.kind] || {
      cls: 'info',
      icon: 'check'
    };
    const row = document.createElement('div');
    row.className = 'notif-item' + (n.read ? '' : ' unread');
    if (CAN_WRITE) {
      row.setAttribute('role', 'button');
      row.tabIndex = 0;
    }
    const ic = document.createElement('div');
    ic.className = 'notif-ic ' + style.cls;
    ic.innerHTML = NOTIF_ICONS[style.icon] || NOTIF_ICONS.check;
    const body = document.createElement('div');
    body.className = 'notif-body';
    const title = document.createElement('div');
    title.className = 'notif-title';
    title.textContent = n.title || '';
    const sub = document.createElement('div');
    sub.className = 'notif-sub';
    sub.textContent = n.body || n.host || '';
    const time = document.createElement('div');
    time.className = 'notif-time';
    time.textContent = notifRelTime(n.created_at);
    body.append(title, sub, time);
    const x = document.createElement('button');
    x.className = 'notif-x';
    x.setAttribute('aria-label', 'Dismiss');
    x.innerHTML = '&times;';
    x.addEventListener('click', e => {
      e.stopPropagation();
      dismissNotif(n.id);
    });
    const activate = () => {
      if (CAN_WRITE) markNotifRead(n.id);
    };
    row.addEventListener('click', activate);
    row.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        activate();
      }
    });
    row.append(ic, body);
    if (CAN_WRITE) row.append(x);
    list.appendChild(row);
  }
}
export async function loadNotifications() {
  try {
    const data = await apiJSON('/api/notifications');
    state.notifItems = data.data || [];
    setNotifBadge(data.unread || 0);
    renderNotifPanel();
  } catch (e) {/* keep the current badge; a transient failure is not fatal */}
}
export function toggleNotifPanel(event) {
  if (event) event.stopPropagation();
  const panel = document.getElementById('notif-panel');
  const willOpen = panel.classList.contains('hidden');
  panel.classList.toggle('hidden', !willOpen);
  document.getElementById('notif-bell').setAttribute('aria-expanded', String(willOpen));
  if (willOpen) loadNotifications();
}
export async function markNotifRead(id) {
  const n = state.notifItems.find(x => x.id === id);
  if (n && !n.read) {
    n.read = true;
    setNotifBadge(state.notifUnread - 1);
    renderNotifPanel();
  }
  try {
    await api('/api/notifications/' + id + '/read', {
      method: 'POST'
    });
  } catch (e) {}
}
export async function markAllNotifsRead() {
  state.notifItems.forEach(n => {
    n.read = true;
  });
  setNotifBadge(0);
  renderNotifPanel();
  try {
    await api('/api/notifications/read', {
      method: 'POST'
    });
  } catch (e) {}
}
export async function dismissNotif(id) {
  const wasUnread = state.notifItems.some(x => x.id === id && !x.read);
  state.notifItems = state.notifItems.filter(x => x.id !== id);
  if (wasUnread) setNotifBadge(state.notifUnread - 1);
  renderNotifPanel();
  try {
    await api('/api/notifications/' + id, {
      method: 'DELETE'
    });
  } catch (e) {}
}
export async function deleteAllNotifs() {
  state.notifItems = [];
  setNotifBadge(0);
  renderNotifPanel();
  try {
    await api('/api/notifications', {
      method: 'DELETE'
    });
  } catch (e) {}
}

// A click anywhere outside the bell closes the panel.
export function showToast(opts) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const cls = opts.cls || 'info';
  const el = document.createElement('div');
  el.className = 'toast';
  el.innerHTML = '<div class="toast-body">' + '<div class="toast-ic ' + cls + '">' + (NOTIF_ICONS[opts.icon] || NOTIF_ICONS.check) + '</div>' + '<div class="toast-main"><div class="toast-title"></div><div class="toast-sub"></div></div>' + '<button class="toast-x" aria-label="Dismiss">&times;</button>' + '</div>' + '<div class="toast-prog ' + cls + ' run"></div>';
  el.querySelector('.toast-title').textContent = opts.title || '';
  el.querySelector('.toast-sub').textContent = opts.sub || '';
  container.prepend(el);
  const remove = () => {
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 280);
  };
  const timer = setTimeout(remove, 4500);
  el.querySelector('.toast-x').addEventListener('click', () => {
    clearTimeout(timer);
    remove();
  });
}
export function toastForNotification(n) {
  const style = NOTIF_STYLE[n.kind] || {
    cls: 'info',
    icon: 'check'
  };
  showToast({
    cls: style.cls,
    icon: style.icon,
    title: n.title,
    sub: n.body || n.host || ''
  });
}
