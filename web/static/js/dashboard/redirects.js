import { apiJSON } from './api.js';
import { esc, safeURL, countLabel } from './format.js';
import { state } from './state.js';

// nodeObservationBadges renders a node's directory presence as a single chip.
//
// It used to emit four: separate confirmed / unknown / legacy counts, a
// Cross-Host / Cross-Scope flag, and a "Redirect details" button that opened a
// modal from the middle of the list. That was noise. Now the row carries one
// "N directories" chip -- N is the node's total directory findings -- and the
// confirmed/unknown/legacy split lives where the detail belongs: the node's own
// Directories tab, one click away.
//
// When the node has cross-host or cross-scope redirects the same chip turns
// into the way to inspect them: it reads as an alert and, on hover or focus,
// summarises the destinations the way the Findings chip summarises severities.
// The full source -> destination list stays on the node's Directories tab.
export function nodeObservationBadges(s) {
  const host = esc(s.host || '');
  const total = s.dir_count || 0;
  if (total <= 0) return '';
  const label = `${countLabel(total)} ${total === 1 ? 'directory' : 'directories'}`;
  const hasRedirects = s.cross_host_count > 0 || s.cross_scope_count > 0;
  if (!hasRedirects) {
    return `<span class="chroma-obs-badge chroma-obs-badge--idle" title="Total directories discovered for this node">${label}</span>`;
  }
  return `<button type="button" data-action="show-redirect-summary" data-host="${host}" aria-label="${label}; this node redirects off-scope, focus for destinations" aria-describedby="severity-tooltip" aria-expanded="false" class="findings-summary-badge chroma-obs-badge chroma-obs-badge--warn">${label}</button>`;
}
export function renderRedirectSummary(rows) {
  const content = document.getElementById('severity-tooltip-content');
  content.innerHTML = rows.slice(0, 5).map(r => `<div class="py-1"><span class="font-mono break-all">${esc(r.destination_host)}</span> · ${esc(r.count)}<br><small>${r.kind === 'cross_host' ? 'Cross-host' : 'Cross-scope'} · ${r.previously_enumerated ? 'previously enumerated in this scan' : 'not previously enumerated in this scan'}</small></div>`).join('') || 'No redirect observations';
  const note = document.createElement('p');
  note.textContent = rows.length > 5 ? 'Open the node for every destination and its source URLs.' : 'Open the node for source and destination URLs.';
  content.appendChild(note);
}
let detailsState = null;
let detailsRequest = 0;
export async function showRedirectDetails(host, page = 1) {
  const dialog = document.getElementById('redirect-details-dialog');
  detailsState = {host, page};
  const request = ++detailsRequest;
  document.getElementById('redirect-details-title').textContent = `Redirect observations · ${host}`;
  const list = document.getElementById('redirect-details-list');
  list.textContent = 'Loading…';
  if (!dialog.open) dialog.showModal();
  try {
    const result = await apiJSON(`/api/profiles/${encodeURIComponent(state.viewState.profile)}/redirects?host=${encodeURIComponent(host)}&page=${page}&size=25`);
    if (request !== detailsRequest || !dialog.open) return;
    list.innerHTML = (result.data || []).map(r => `<li><strong>${r.Kind === 'cross_host' ? 'Cross-Host Redirect' : 'Cross-Scope Redirect'}</strong><dl><dt>Source · HTTP ${esc(r.StatusCode)}</dt><dd class="break-all">${esc(r.SourceURL)}</dd><dt>Destination</dt><dd class="break-all"><a href="${esc(safeURL(r.DestinationURL))}" target="_blank" rel="noopener noreferrer">${esc(r.DestinationURL)}</a></dd><dt>Enumeration</dt><dd>${r.PreviouslyEnumerated ? 'Previously enumerated in this scan' : 'Not previously enumerated in this scan'}</dd><dt>Observed</dt><dd>${esc(new Date(r.ObservedAt).toLocaleString())}</dd></dl></li>`).join('') || 'No redirect observations';
    detailsState.page = result.page.page;
    document.getElementById('redirect-details-page').textContent = `Page ${result.page.page} / ${result.page.total_pages} · ${result.page.total_rows} observations`;
    document.getElementById('redirect-details-prev').disabled = result.page.page <= 1;
    document.getElementById('redirect-details-next').disabled = result.page.page >= result.page.total_pages;
  } catch {
    if (request === detailsRequest) list.textContent = 'Unable to load redirect observations';
  }
}
export function setupRedirectDetails() {
  const dialog = document.getElementById('redirect-details-dialog');
  document.getElementById('redirect-details-close').addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => { detailsRequest++; });
  document.getElementById('redirect-details-prev').addEventListener('click', () => showRedirectDetails(detailsState.host, Math.max(1, detailsState.page - 1)));
  document.getElementById('redirect-details-next').addEventListener('click', () => showRedirectDetails(detailsState.host, detailsState.page + 1));
}
