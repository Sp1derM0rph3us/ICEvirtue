import { HOME_SEVERITY_COLORS, UUID_RE, state } from './state.js';
import { apiJSON } from './api.js';
import { writeViewState } from './url.js';
import { hideSeverityTooltip, renderNewFindingsBadge } from "./findings.js";
import { switchDiscTab, switchView, openSubDashboard } from "./navigation.js";
export function overviewUTC(raw) {
  if (!raw) return 'Never';
  const date = new Date(raw);
  if (Number.isNaN(date.getTime()) || date.getUTCFullYear() < 2000) return 'Never';
  return `${date.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}
export function renderOverviewBar(id, parts, label) {
  const track = document.getElementById(id);
  track.replaceChildren();
  track.setAttribute('aria-label', label);
  const total = parts.reduce((sum, part) => sum + part.count, 0);
  if (!total) return;
  for (const part of parts) {
    if (!part.count) continue;
    const segment = document.createElement('span');
    segment.style.width = `${part.count / total * 100}%`;
    segment.style.backgroundColor = part.color;
    segment.title = `${part.label}: ${part.count.toLocaleString()}`;
    track.appendChild(segment);
  }
}
export function openHomeFinding(host) {
  state.viewState.profile = state.viewState.homeProfile;
  document.getElementById('select-profile').value = state.viewState.profile;
  state.currentRows = [];
  state.pendingNewFindings = {};
  state.severitySummaryCache = new Map();
  hideSeverityTooltip();
  renderNewFindingsBadge();
  switchDiscTab('subs', false);
  switchView('findings', false);
  openSubDashboard(host, host);
}
export function renderHomeOverview(data) {
  document.getElementById('home-asset-total').textContent = data.assets.total.toLocaleString();
  document.getElementById('home-last-scan').textContent = overviewUTC(data.profile.last_scan_utc);
  document.getElementById('home-last-scan-status').textContent = data.profile.last_scan_status || 'No scan recorded';
  document.getElementById('home-last-change').textContent = overviewUTC(data.last_identified_change_utc);
  document.getElementById('home-scan-badge').classList.toggle('hidden', !data.profile.is_scanning && !data.profile.is_queued);
  document.getElementById('home-scan-state').textContent = data.profile.is_scanning ? 'Scan in progress' : 'Scan queued';
  const wafList = document.getElementById('home-waf-list');
  wafList.replaceChildren();
  const wafs = data.detected_wafs || [];
  document.getElementById('home-waf-empty').classList.toggle('hidden', wafs.length > 0);
  document.getElementById('home-waf-count').textContent = wafs.length.toLocaleString();
  for (const name of wafs) {
    const item = document.createElement('li');
    item.className = 'chroma-waf-chip';
    item.textContent = name;
    wafList.appendChild(item);
  }
  const observed = data.assets.http_observed;
  const total = data.assets.total;
  const unobserved = total - observed;
  document.getElementById('home-response-ratio').textContent = `${observed.toLocaleString()} / ${total.toLocaleString()}`;
  document.getElementById('home-observed-count').textContent = observed.toLocaleString();
  document.getElementById('home-unobserved-count').textContent = unobserved.toLocaleString();
  renderOverviewBar('home-response-track', [{
    label: 'HTTP response observed',
    count: observed,
    color: 'var(--ui-rose)'
  }, {
    label: 'No HTTP response recorded',
    count: unobserved,
    color: 'var(--ui-track)'
  }], `${observed} of ${total} assets have an HTTP response recorded`);
  const severities = data.finding_severities || [];
  const findingTotal = severities.reduce((sum, item) => sum + item.count, 0);
  document.getElementById('home-severity-total').textContent = findingTotal.toLocaleString();
  document.getElementById('home-severity-empty').classList.toggle('hidden', findingTotal > 0);
  const meters = document.getElementById('home-severity-meters');
  meters.replaceChildren();
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  // Each bar is scaled to the largest severity bucket, so the tallest count
  // fills the track and the rest read as a proportion of it.
  const severityMax = Math.max(1, ...severities.map(item => item.count));
  for (const name of severityOrder) {
    const item = severities.find(entry => entry.severity === name) || {
      severity: name,
      count: 0
    };
    const row = document.createElement('div');
    row.className = 'st-sev-row';
    const label = document.createElement('span');
    label.className = 'st-sev-label';
    label.textContent = {
      critical: 'CRIT',
      high: 'HIGH',
      medium: 'MED',
      low: 'LOW',
      info: 'INFO'
    }[name] || name.toUpperCase();
    const track = document.createElement('span');
    track.className = 'st-sev-track';
    const fill = document.createElement('i');
    fill.style.width = `${item.count / severityMax * 100}%`;
    fill.style.background = HOME_SEVERITY_COLORS[name];
    track.appendChild(fill);
    const count = document.createElement('span');
    count.className = 'st-sev-n';
    count.textContent = item.count.toLocaleString();
    row.append(label, track, count);
    meters.appendChild(row);
  }
  const list = document.getElementById('home-priority-findings');
  list.replaceChildren();
  const findings = data.priority_findings || [];
  document.getElementById('home-priority-empty').classList.toggle('hidden', findings.length > 0);
  for (const finding of findings) {
    const row = document.createElement('li');
    row.className = 'overview-priority-item py-3 flex flex-wrap items-start gap-x-4 gap-y-2';
    const badge = document.createElement('span');
    badge.className = finding.severity === 'critical' ? 'chroma-priority-badge chroma-priority-badge--critical' : 'chroma-priority-badge chroma-priority-badge--high';
    badge.textContent = finding.severity;
    row.appendChild(badge);
    const details = document.createElement('div');
    details.className = 'min-w-0 flex-1';
    const title = finding.host && finding.has_asset ? document.createElement('button') : document.createElement('p');
    title.className = finding.host && finding.has_asset ? 'text-left text-sm font-bold text-white hover:text-accent break-words' : 'text-sm font-bold text-white break-words';
    title.textContent = finding.name || 'Unnamed finding';
    if (finding.host && finding.has_asset) {
      title.type = 'button';
      title.addEventListener('click', () => openHomeFinding(finding.host));
    }
    details.appendChild(title);
    const asset = document.createElement('p');
    asset.className = 'font-mono text-xs chroma-accent break-all mt-1';
    asset.textContent = finding.host || finding.url || 'Unattributed finding';
    details.appendChild(asset);
    const seen = document.createElement('p');
    seen.className = 'text-xs text-slate-500 mt-1';
    seen.textContent = `Last observed: ${overviewUTC(finding.last_seen_utc)}`;
    details.appendChild(seen);
    row.appendChild(details);
    list.appendChild(row);
  }
}
export async function loadHomeOverview() {
  const id = state.viewState.homeProfile;
  const request = ++state.homeOverviewRequest;
  if (!state.profileIndexReady) {
    document.getElementById('home-empty').classList.add('hidden');
    document.getElementById('home-content').classList.add('hidden');
    document.getElementById('home-loading').classList.add('hidden');
    document.getElementById('home-error-text').textContent = 'Could not load profiles. Please retry.';
    document.getElementById('home-error').classList.remove('hidden');
    return;
  }
  document.getElementById('home-empty').classList.toggle('hidden', !!id);
  document.getElementById('home-content').classList.add('hidden');
  document.getElementById('home-error').classList.add('hidden');
  document.getElementById('home-loading').classList.toggle('hidden', !id);
  document.getElementById('home-scan-badge').classList.add('hidden');
  if (!id) return;
  try {
    const data = await apiJSON(`/api/profiles/${encodeURIComponent(id)}/overview`);
    if (request !== state.homeOverviewRequest || id !== state.viewState.homeProfile || state.viewState.view !== 'home') return;
    renderHomeOverview(data);
    document.getElementById('home-content').classList.remove('hidden');
  } catch (err) {
    if (request !== state.homeOverviewRequest || id !== state.viewState.homeProfile || state.viewState.view !== 'home') return;
    document.getElementById('home-error-text').textContent = `Could not load the profile overview: ${err.message}`;
    document.getElementById('home-error').classList.remove('hidden');
  } finally {
    if (request === state.homeOverviewRequest) document.getElementById('home-loading').classList.add('hidden');
  }
}
export function onHomeProfileChanged() {
  const select = document.getElementById('select-home-profile');
  state.viewState.homeProfile = UUID_RE.test(select.value) ? select.value : null;
  writeViewState();
  loadHomeOverview();
}

// esc renders untrusted text into an HTML context.
//
// Almost nothing this dashboard displays is its own copy: a subdomain name
// comes from subfinder, a finding title from whoever wrote the nuclei
// template, a secret value out of somebody else's JavaScript. All of it is
// attacker-influenced, so none of it may reach innerHTML unescaped.
