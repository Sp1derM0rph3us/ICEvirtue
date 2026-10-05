import { SEVERITY_TOOLTIP_DELAY, mobileLayout, state } from './state.js';
import { apiJSON } from './api.js';
import { activeView, writeViewState } from './url.js';
import { setSubDashboardOpen, syncControlsBar, switchSubDashboardTab } from "./navigation.js";
import { severityClass, esc, countLabel, safeURL } from "./format.js";
export function hideSeverityTooltip() {
  clearTimeout(state.severityTooltipTimer);
  state.severityTooltipTimer = null;
  if (state.severityTooltipBadge) state.severityTooltipBadge.setAttribute('aria-expanded', 'false');
  state.severityTooltipBadge = null;
  state.severityTooltipRequest++;
  document.getElementById('severity-tooltip').classList.add('hidden');
}
export function placeSeverityTooltip(badge) {
  const tooltip = document.getElementById('severity-tooltip');
  const rect = badge.getBoundingClientRect();
  const halfWidth = Math.min(tooltip.offsetWidth || 176, window.innerWidth - 32) / 2;
  const center = Math.max(halfWidth + 16, Math.min(window.innerWidth - halfWidth - 16, rect.left + rect.width / 2));
  const fitsAbove = rect.top >= (tooltip.offsetHeight || 90) + 16;
  tooltip.style.left = `${center}px`;
  tooltip.style.top = `${fitsAbove ? rect.top - 8 : rect.bottom + 8}px`;
  tooltip.style.transform = fitsAbove ? 'translate(-50%, -100%)' : 'translate(-50%, 0)';
}
export function renderSeverityTooltip(rows) {
  const content = document.getElementById('severity-tooltip-content');
  content.innerHTML = rows.map(row => `
                <div class="flex items-center justify-between gap-5 py-0.5 font-mono uppercase">
                    <span class="${severityClass(String(row.severity || '').toLowerCase())}">${esc(row.severity)}</span>
                    <span class="font-bold text-slate-100">${esc(row.count)}</span>
                </div>`).join('');
}
export function openSeverityTooltip(badge) {
  if (!badge || !state.viewState.profile) return;
  if (state.severityTooltipBadge === badge && !document.getElementById('severity-tooltip').classList.contains('hidden')) return;
  clearTimeout(state.severityTooltipTimer);
  state.severityTooltipTimer = null;
  if (state.severityTooltipBadge && state.severityTooltipBadge !== badge) state.severityTooltipBadge.setAttribute('aria-expanded', 'false');
  state.severityTooltipBadge = badge;
  badge.setAttribute('aria-expanded', 'true');
  const tooltip = document.getElementById('severity-tooltip');
  const content = document.getElementById('severity-tooltip-content');
  const host = badge.dataset.host;
  const cacheKey = `${state.viewState.profile}:${host}`;
  const request = ++state.severityTooltipRequest;
  tooltip.classList.remove('hidden');
  placeSeverityTooltip(badge);
  const cached = state.severitySummaryCache.get(cacheKey);
  if (cached) {
    renderSeverityTooltip(cached);
    return;
  }
  content.textContent = 'Loading…';
  apiJSON(`/api/profiles/${encodeURIComponent(state.viewState.profile)}/vulnerabilities/severity-summary?host=${encodeURIComponent(host)}`).then(rows => {
    if (request !== state.severityTooltipRequest || state.severityTooltipBadge !== badge) return;
    const summary = Array.isArray(rows) ? rows : [];
    state.severitySummaryCache.set(cacheKey, summary);
    renderSeverityTooltip(summary);
    placeSeverityTooltip(badge);
  }).catch(() => {
    if (request === state.severityTooltipRequest && state.severityTooltipBadge === badge) {
      content.textContent = 'Unable to load breakdown';
    }
  });
}
export function scheduleSeverityTooltip(badge) {
  clearTimeout(state.severityTooltipTimer);
  state.severityTooltipTimer = setTimeout(() => openSeverityTooltip(badge), SEVERITY_TOOLTIP_DELAY);
}

// buildSubRow reads the counts and the status straight off the row.
//
// It used to derive all four by scanning the profile's entire vulnerability,
// directory, secret and host arrays, once per rendered row. That is the ~227
// million string comparisons per render this endpoint was rebuilt to remove.
export function buildSubRow(s) {
  const domain = esc(s.domain);
  const firstSeen = new Date(s.first_seen).toLocaleDateString();
  const lastChanged = new Date(s.last_changed).toLocaleDateString();
  let statusHtml;
  if (s.status_code == null) {
    statusHtml = `<span class="chroma-status chroma-status--idle">No response</span>`;
  } else {
    const code = s.status_code;
    let statusClass = 'bg-slate-900 text-slate-600 border-slate-800';
    if (code === 200) statusClass = 'bg-emerald-950/30 text-emerald-500 border-emerald-900/50';else if (code === 301 || code === 302 || code === 307) statusClass = 'bg-blue-950/30 text-blue-400 border-blue-900/50';else if (code === 403 || code === 401) statusClass = 'bg-orange-950/30 text-orange-400 border-orange-900/50';else if (code >= 500) statusClass = 'bg-rose-950/30 text-rose-500 border-rose-900/50';
    statusHtml = `<span class="px-3 py-1 border rounded-sm text-[11px] font-sans font-black tracking-widest ${statusClass}">${code}</span>`;
  }
  let findingsHtml = '';
  if (!s.vuln_count && !s.dir_count && !s.secret_count) {
    findingsHtml = `<span class="text-slate-800 text-xs font-sans font-black tracking-widest">---</span>`;
  } else {
    if (s.vuln_count > 0) findingsHtml += `<button type="button" data-action="show-severity-summary" data-host="${esc(s.host)}" aria-label="${countLabel(s.vuln_count)} Nuclei findings; focus for severity breakdown" aria-describedby="severity-tooltip" aria-expanded="false" class="findings-summary-badge chroma-finding-badge inline-flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-sans font-black">${countLabel(s.vuln_count)} Findings</button> `;
    if (s.dir_count > 0) findingsHtml += `<span class="chroma-status chroma-status--idle">${countLabel(s.dir_count)} directories</span> `;
    if (s.secret_count > 0) findingsHtml += `<span class="chroma-status chroma-status--idle">${countLabel(s.secret_count)} credentials</span>`;
  }

  // A node can only be opened when it has a correlation key. Without one there
  // are no findings to scope to it, so the link would open an empty view.
  const nameCell = s.host ? `<button data-action="open-node" data-domain="${esc(s.host)}" data-label="${domain}" class="hover:text-white transition-colors text-left uppercase tracking-tight">${domain}</button>` : `<span class="uppercase tracking-tight opacity-40" title="No usable host, so no findings can be attributed to it">${domain}</span>`;
  const tr = document.createElement('tr');
  tr.className = 'hover:bg-accent/[0.04] transition-colors group';
  tr.innerHTML = `
                <td class="p-5 text-slate-700 font-mono font-bold text-xs">#${esc(s.id)}</td>
                <td class="p-5 font-mono font-bold text-accent text-sm">${nameCell}</td>
                <td class="p-5 text-center">${statusHtml}</td>
                <td class="p-5 text-center"><div class="flex items-center justify-center gap-1.5 flex-wrap">${findingsHtml}</div></td>
                <td class="p-5 text-right text-xs text-slate-500 font-sans font-bold tracking-tighter"><span>${esc(firstSeen)}</span></td>
                <td class="p-5 text-right text-xs text-slate-500 font-sans font-bold tracking-tighter">
                    <div class="chroma-node-last flex justify-end items-center gap-2">
                        <span>${esc(lastChanged)}</span>
                        <a href="${esc(safeURL('http://' + s.domain))}" target="_blank" rel="noopener noreferrer" class="chroma-node-open" aria-label="Open ${domain} in a browser" title="Open ${domain} in a browser">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                        </a>
                    </div>
                </td>
            `;
  return tr;
}
export function secretSource(s) {
  const original = safeURL(s.SourceURL);
  if (original === '#') return '<span class="chroma-muted">Unattributed</span>';
  const link = (href, label) => `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer" class="text-accent hover:text-white transition-colors" title="${esc(href)}">${label} &rarr;</a>`;
  const archived = safeURL(s.ArchiveURL || '');
  if (archived === '#') return link(original, 'Open source');
  return `${link(original, s.SeenLive ? 'Live file' : 'Original URL')}<br>${link(archived, s.ArchiveURL.includes('web.archive.org/') ? 'Archived file' : 'Archive record')}`;
}
export function secretContext(s) {
  const entries = Array.isArray(s.Context) ? s.Context : [];
  return entries.length ? entries.map(value => `<div class="break-all">• ${esc(value)}</div>`).join('') : '<span class="chroma-muted">None recorded</span>';
}
export function buildSecretRow(s, node = false) {
  const tr = document.createElement('tr');
  tr.className = 'hover:bg-accent/[0.04] transition-colors group';
  const pad = node ? 'p-4' : 'p-5';
  tr.innerHTML = `
                <td class="${pad} font-sans"><span class="px-3 py-1.5 bg-accent/10 text-accent border border-accent/30 rounded-sm text-[10px] font-sans font-black tracking-widest uppercase">${esc(s.SecretType)}</span></td>
                <td class="${pad} font-mono text-sm text-slate-200 break-all select-all font-bold tracking-tight">${esc(s.SecretValue)}</td>
                <td class="${pad} text-xs font-sans font-bold">${secretSource(s)}</td>
                <td class="${pad} text-xs font-sans font-bold">${esc(s.Engine || 'Unknown')}</td>
                ${node ? `<td class="${pad} text-xs font-sans">
                    <div>Risk: ${esc(s.Risk || 'Unknown')}</div>
                    <div>Occurrences: ${s.Occurrences > 0 ? esc(s.Occurrences) : '—'}</div>
                    <details><summary class="text-accent cursor-pointer">Description and context</summary>
                        <div class="mt-2 break-words">${esc(s.Description || 'No description recorded')}</div>
                        <div class="mt-2">${secretContext(s)}</div>
                    </details>
                </td>` : ''}
            `;
  return tr;
}
export function buildVulnRow(v) {
  const severity = String(v.Severity || '').toLowerCase();
  let sevClass = 'bg-slate-900 text-slate-600 border-slate-800';
  if (severity === 'critical') sevClass = 'bg-rose-950/40 text-rose-500 border-rose-900/50';else if (severity === 'high') sevClass = 'bg-orange-950/40 text-orange-400 border-orange-900/50';else if (severity === 'medium') sevClass = 'bg-amber-950/40 text-amber-500 border-amber-900/50';else if (severity === 'low') sevClass = 'bg-emerald-950/40 text-emerald-500 border-emerald-900/50';
  const tr = document.createElement('tr');
  tr.className = 'hover:bg-accent/[0.04] transition-colors group';
  tr.innerHTML = `
                <td class="p-4"><span class="px-3 py-1.5 border rounded-sm text-[10px] font-sans font-black uppercase tracking-widest ${sevClass}">${esc(v.Severity)}</span></td>
                <td class="p-4 font-sans font-bold text-slate-200 tracking-tight text-sm">${esc(v.Name)}</td>
                <td class="p-4 font-mono text-xs text-slate-600 group-hover:text-slate-400 transition-colors uppercase font-bold">${esc(v.TemplateID)}</td>
            `;
  return tr;
}
export function buildDirRow(d) {
  let statusClass = 'bg-slate-900 text-slate-600 border-slate-800';
  if (d.StatusCode === 200) statusClass = 'bg-emerald-950/40 text-emerald-500 border-emerald-900/50';else if (d.StatusCode === 301 || d.StatusCode === 302 || d.StatusCode === 307) statusClass = 'bg-blue-950/40 text-blue-400 border-blue-900/50';else if (d.StatusCode === 403 || d.StatusCode === 401) statusClass = 'bg-orange-950/40 text-orange-400 border-orange-900/50';
  const tr = document.createElement('tr');
  tr.className = 'hover:bg-accent/[0.04] transition-colors group';
  tr.innerHTML = `
                <td class="p-4"><span class="px-3 py-1.5 border rounded-sm text-[11px] font-sans font-black tracking-widest ${statusClass}">${esc(d.StatusCode)}</span></td>
                <td class="p-4 font-mono text-xs font-bold tracking-tight"><a href="${esc(safeURL(d.DirURL))}" target="_blank" rel="noopener noreferrer" class="text-accent hover:text-white transition-colors break-all">${esc(d.DirURL)}</a></td>
            `;
  return tr;
}
export function mobileCard(title, fields, actions = '') {
  const li = document.createElement('li');
  li.className = 'chroma-mobile-card';
  li.innerHTML = `<h3>${title}</h3><dl>${fields.map(([label, value]) => `<dt>${label}</dt><dd>${value}</dd>`).join('')}</dl>${actions ? `<div class="chroma-mobile-actions">${actions}</div>` : ''}`;
  return li;
}
export function buildSubCard(s) {
  const domain = esc(s.domain);
  const host = esc(s.host || '');
  const title = s.host ? `<button type="button" data-action="open-node" data-domain="${host}" data-label="${domain}" class="chroma-accent text-left">${domain}</button>` : domain;
  const status = s.status_code == null ? 'No response recorded' : esc(s.status_code);
  const badges = [s.vuln_count > 0 ? `<button type="button" data-action="show-severity-summary" data-host="${host}" aria-label="${countLabel(s.vuln_count)} Nuclei findings; focus for severity breakdown" aria-describedby="severity-tooltip" aria-expanded="false" class="findings-summary-badge chroma-finding-badge px-2 py-1">${countLabel(s.vuln_count)} Findings</button>` : '', s.dir_count > 0 ? `<span class="chroma-status chroma-status--idle">${countLabel(s.dir_count)} directories</span>` : '', s.secret_count > 0 ? `<span class="chroma-status chroma-status--idle">${countLabel(s.secret_count)} credentials</span>` : ''].filter(Boolean).join(' ');
  const actions = s.host ? `<button type="button" data-action="open-node" data-domain="${host}" data-label="${domain}" class="chroma-button-secondary">Open node</button>` : '';
  return mobileCard(title, [['HTTP status', status], ['Observations', badges || 'None recorded'], ['First seen', esc(new Date(s.first_seen).toLocaleDateString())], ['Last sync', esc(new Date(s.last_changed).toLocaleDateString())]], actions);
}
export function buildSecretCard(s, node = false) {
  const fields = [['Value', `<span class="select-all font-mono">${esc(s.SecretValue)}</span>`], ['Source', secretSource(s)], ['Engine', esc(s.Engine || 'Unknown')]];
  if (node) fields.push(['Risk', esc(s.Risk || 'Unknown')], ['Occurrences', s.Occurrences > 0 ? esc(s.Occurrences) : '—'], ['Description', esc(s.Description || 'No description recorded')], ['Context', secretContext(s)]);
  return mobileCard(esc(s.SecretType || 'Credential'), fields);
}
export function buildVulnCard(v) {
  const severity = String(v.Severity || 'Unknown').toLowerCase();
  const level = severity === 'critical' ? 'chroma-priority-badge--critical' : severity === 'high' ? 'chroma-priority-badge--high' : '';
  return mobileCard(esc(v.Name || 'Unnamed finding'), [['Severity', `<span class="chroma-priority-badge ${level}">${esc(v.Severity || 'Unknown')}</span>`], ['Template', `<code>${esc(v.TemplateID)}</code>`]]);
}
export function buildDirCard(d) {
  return mobileCard(esc(d.DirURL), [['HTTP status', esc(d.StatusCode)], ['URL', `<a href="${esc(safeURL(d.DirURL))}" target="_blank" rel="noopener noreferrer">Open directory URL</a>`]]);
}
export function renderRows(tbodyId, mobileId, rows, tableBuilder, cardBuilder, colspan, emptyMessage) {
  const mobile = document.getElementById(mobileId);
  mobile.replaceChildren();
  if (mobileLayout.matches) {
    document.getElementById(tbodyId).replaceChildren();
    if (!rows.length) {
      const item = document.createElement('li');
      item.className = 'chroma-mobile-empty';
      item.textContent = emptyMessage;
      mobile.appendChild(item);
      return;
    }
    const frag = document.createDocumentFragment();
    rows.forEach(row => frag.appendChild(cardBuilder(row)));
    mobile.appendChild(frag);
  } else {
    fillTable(tbodyId, rows, tableBuilder, colspan, emptyMessage);
  }
}
export function clearInactiveResultRows() {
  ['tbody-subs', 'tbody-secs', 'tbody-sub-vulns', 'tbody-sub-dirs', 'tbody-sub-secs', 'subs-mobile', 'secs-mobile', 'node-mobile'].forEach(id => document.getElementById(id).replaceChildren());
}
export function fillTable(tbodyId, rows, build, colspan, emptyMessage) {
  const tbody = document.getElementById(tbodyId);
  tbody.innerHTML = '';
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="${colspan}" class="p-12 text-center text-slate-700 font-sans font-black tracking-[0.2em] uppercase italic bg-black/40 text-xs">${esc(emptyMessage)}</td></tr>`;
    return;
  }
  const frag = document.createDocumentFragment();
  rows.forEach(r => frag.appendChild(build(r)));
  tbody.appendChild(frag);
}

// ------------------------------------------------------------------- the pager
export function renderPager() {
  const pager = document.getElementById('pager');
  const showing = state.pageMeta.total_rows > 0;
  pager.classList.toggle('hidden', !showing);
  pager.classList.toggle('flex', showing);
  if (!showing) return;
  const from = (state.pageMeta.page - 1) * state.pageMeta.size + 1;
  const to = Math.min(state.pageMeta.page * state.pageMeta.size, state.pageMeta.total_rows);
  document.getElementById('pager-summary').textContent = `${from}–${to} of ${state.pageMeta.total_rows}`;
  document.getElementById('pager-position').textContent = `Page ${state.pageMeta.page} / ${state.pageMeta.total_pages}`;
  const atFirst = state.pageMeta.page <= 1;
  const atLast = state.pageMeta.page >= state.pageMeta.total_pages;
  const set = (which, disabled) => {
    document.querySelector(`#pager [data-pager="${which}"]`).disabled = disabled;
  };
  set('first', atFirst);
  set('prev', atFirst);
  set('next', atLast);
  set('last', atLast);
}
export function renderNewFindingsBadge() {
  const badge = document.getElementById('new-findings-badge');
  const total = Object.values(state.pendingNewFindings).reduce((a, b) => a + b, 0);
  badge.classList.toggle('hidden', total === 0);
  badge.classList.toggle('flex', total > 0);
  if (total === 0) return;
  const parts = Object.entries(state.pendingNewFindings).map(([kind, n]) => `${n} ${kind}`).join(', ');
  document.getElementById('new-findings-text').textContent = `${parts} — refresh`;
}

// ------------------------------------------------------------------ loading

// loadCurrentView fetches exactly one page of whatever is on screen.
//
// One request, for one page, for one tab. The dashboard used to issue five
// parallel chains that paged the entire profile -- around 55 requests -- on every
// profile switch and every eight seconds during a scan.
export async function loadCurrentView() {
  if (!state.viewState.profile) {
    showEmptyState(true);
    return;
  }

  // Serialise. Without this the SSE refresh could stack a second full load onto
  // an unfinished one, and the two would race to write the same table.
  if (state.inFlight) {
    state.inFlight.abort = true;
  }
  const token = {
    abort: false
  };
  state.inFlight = token;
  writeViewState();
  showLoader(true);
  const base = `/api/profiles/${encodeURIComponent(state.viewState.profile)}`;
  const params = new URLSearchParams({
    page: String(state.viewState.page),
    size: String(state.viewState.size)
  });
  let path;
  const view = activeView();
  if (view === 'subs') {
    params.set('sort', state.viewState.sort);
    if (state.viewState.filter) params.set('filter', state.viewState.filter);
    path = `${base}/subdomains`;
  } else if (view === 'secs') {
    path = `${base}/secrets`;
  } else {
    // A node's tab. host scopes it server-side, replacing three client-side
    // filter passes over the whole dataset.
    params.set('host', state.viewState.node);
    path = view === 'dirs' ? `${base}/directories` : view === 'nodesecs' ? `${base}/secrets` : `${base}/vulnerabilities`;
  }
  try {
    const body = await apiJSON(`${path}?${params}`);
    if (token.abort) return;
    state.currentRows = body.data || [];
    state.pageMeta = body.page || state.pageMeta;

    // The server is the authority on what it served: it clamps size and pulls
    // an out-of-range page back into the set. Adopting its answer is what keeps
    // the pager from describing a page that does not exist.
    state.viewState.page = state.pageMeta.page;
    state.viewState.size = state.pageMeta.size;
    writeViewState();
    renderCurrentView();
  } catch (err) {
    if (token.abort) return;
    // Nothing to report while navigating away: api() has already decided the
    // session is gone, and painting "session expired" into the table would be
    // a confusing flash on the way to the login page.
    if (state.leaving) return;
    console.error(err);
    showLoadError(err);
  } finally {
    if (state.inFlight === token) state.inFlight = null;
    showLoader(false);
  }
}
export function showLoadError(err) {
  clearInactiveResultRows();
  const message = `Could not load ${activeView()}: ${err.message}`;
  const target = state.viewState.node ? `tbody-sub-${state.viewState.nodeTab}` : state.viewState.tab === 'secs' ? 'tbody-secs' : 'tbody-subs';
  const colspan = target === 'tbody-sub-dirs' ? 2 : target === 'tbody-secs' ? 4 : target === 'tbody-sub-secs' ? 5 : 3;
  const mobile = state.viewState.node ? 'node-mobile' : state.viewState.tab === 'secs' ? 'secs-mobile' : 'subs-mobile';
  renderRows(target, mobile, [], () => null, () => null, target === 'tbody-subs' ? 6 : colspan, message);
  document.getElementById('pager').classList.add('hidden');
}
export function renderCurrentView() {
  showEmptyState(false);
  clearInactiveResultRows();
  const tSubs = document.getElementById('table-subs');
  const tSecs = document.getElementById('table-secs');
  const view = activeView();
  if (view === 'subs' || view === 'secs') {
    setSubDashboardOpen(false);
    tSubs.classList.toggle('hidden', view !== 'subs');
    tSecs.classList.toggle('hidden', view !== 'secs');
    if (view === 'subs') {
      const message = state.viewState.filter ? 'No nodes match the active filter.' : 'No nodes found yet.';
      renderRows('tbody-subs', 'subs-mobile', state.currentRows, buildSubRow, buildSubCard, 6, message);
    } else {
      renderRows('tbody-secs', 'secs-mobile', state.currentRows, s => buildSecretRow(s), s => buildSecretCard(s), 4, 'No credentials found yet.');
    }
  } else {
    tSubs.classList.add('hidden');
    tSecs.classList.add('hidden');
    renderNodeView();
  }
  renderPager();
  syncControlsBar();
}
export function renderNodeView() {
  const sub = document.getElementById('sub-dashboard');
  sub.classList.remove('hidden');
  sub.classList.add('flex');
  document.getElementById('sub-dash-title').innerHTML = `<span class="chroma-status chroma-status--idle mr-2">Node</span> ${esc(state.viewState.node)}`;
  switchSubDashboardTab(state.viewState.nodeTab, false);
  if (state.viewState.nodeTab === 'vulns') {
    renderRows('tbody-sub-vulns', 'node-mobile', state.currentRows, buildVulnRow, buildVulnCard, 3, 'No findings detected in this node.');
  } else if (state.viewState.nodeTab === 'dirs') {
    renderRows('tbody-sub-dirs', 'node-mobile', state.currentRows, buildDirRow, buildDirCard, 2, 'No directories discovered in this node.');
  } else {
    renderRows('tbody-sub-secs', 'node-mobile', state.currentRows, s => buildSecretRow(s, true), s => buildSecretCard(s, true), 5, 'No credentials found in this node.');
  }
}

// The node's IP is one extra request and only ever a row or two, so it is fetched
// separately rather than widening the index that serves the status badge.
export async function loadNodeAddresses() {
  const request = ++state.nodeInfoRequest;
  const ipEl = document.getElementById('sub-dash-ip');
  const profileID = state.viewState.profile;
  const node = state.viewState.node;
  ipEl.textContent = 'IP: Resolving… | Checking WAF…';
  const [hostResult, wafResult] = await Promise.allSettled([apiJSON(`/api/profiles/${encodeURIComponent(profileID)}/hosts` + `?host=${encodeURIComponent(node)}&size=25`), apiJSON(`/api/profiles/${encodeURIComponent(profileID)}/wafs?host=${encodeURIComponent(node)}`)]);
  if (request !== state.nodeInfoRequest || profileID !== state.viewState.profile || node !== state.viewState.node) return;
  let ipText = 'IP unavailable';
  if (hostResult.status === 'fulfilled') {
    const ips = [...new Set((hostResult.value.data || []).map(h => h.IP).filter(Boolean))];
    ipText = ips.length ? `IP: ${ips.join(', ')}` : 'IP: Unknown';
  } else {
    console.error(hostResult.reason);
  }
  let wafText = 'WAF scan unavailable';
  if (wafResult.status === 'fulfilled') {
    const wafs = wafResult.value;
    wafText = wafs.names.length ? `${wafs.names.join(', ')} detected` : 'No WAF detected';
  } else {
    console.error(wafResult.reason);
  }
  ipEl.textContent = `${ipText}  |  ${wafText}`;
}

// ---------------------------------------------------------------- navigation

export function showEmptyState(show) {
  document.getElementById('empty-state').classList.toggle('hidden', !show);
  if (show) {
    document.getElementById('table-subs').classList.add('hidden');
    document.getElementById('table-secs').classList.add('hidden');
    document.getElementById('pager').classList.add('hidden');
    setSubDashboardOpen(false);
  }
}
export function showLoader(show) {
  document.getElementById('loader').classList.toggle('hidden', !show);
  if (show) {
    document.getElementById('empty-state').classList.add('hidden');
  }
}

// toggleTheme flips the attribute the whole palette hangs off and persists the
// choice. The inline <head> script reapplies it on the next load; without the
// stored value a reload would fall back to the OS preference and appear to
// forget what the operator picked.
