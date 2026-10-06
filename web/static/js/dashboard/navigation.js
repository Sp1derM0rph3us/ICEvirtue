import { NAV_TAB_ACTIVE, NAV_TAB_INACTIVE, NAV_VIEWS, PAGE_SIZES, PILL_ACTIVE, PILL_BASE, PILL_INACTIVE, SORTS, SUB_TABS, TABS, UUID_RE, state } from './state.js';
import { defaultSizeForView, writeViewState } from './url.js';
import { loadHomeOverview } from "./overview.js";
import { loadCurrentView, hideSeverityTooltip, renderNewFindingsBadge, loadNodeAddresses } from "./findings.js";
// setSubDashboardOpen is the single owner of "is a node sub-dashboard showing".
//
// The visibility of the sub-dashboard and of the controls bar have to move
// together, and they used to be toggled by hand in five different places.
// Only closeSubDashboard restored the controls bar, while switchDiscTab,
// showEmptyState(true) and showLoader(true) each closed the sub-dashboard
// without restoring it: opening a node and then clicking the Credentials tab
// made the Sort and Filter bars disappear for the rest of the session, with
// nothing in the UI to bring them back. Those paths also left
// the node still set, which sent the next load down
// the sub-dashboard branch for a node that was no longer on screen.
export function setSubDashboardOpen(open, domain = null) {
  state.viewState.node = open ? domain : null;
  const sub = document.getElementById('sub-dashboard');
  sub.classList.toggle('hidden', !open);
  sub.classList.toggle('flex', open);
  syncControlsBar();
}

// The sort and filter controls only drive the Nodes table, so they are hidden on
// the Credentials tab and inside a node's sub-dashboard. Leaving them visible
// there offered controls that lit up on click and changed nothing.
export function syncControlsBar() {
  const relevant = !state.viewState.node && state.viewState.tab === 'subs';
  document.getElementById('controls-bar').classList.toggle('hidden', !relevant);
}

// api is the only way this page talks to the server.
//
// It carries the timeout that did not exist before, and it names what failed. The
// previous code surfaced every failure as the same fixed string, with the actual
// status only reaching console.error.

export function switchView(view, loadFindings = true) {
  state.viewState.view = NAV_VIEWS.includes(view) ? view : 'home';
  if (state.viewState.view !== 'home') state.homeOverviewRequest++;
  document.getElementById('view-home').classList.toggle('hidden', state.viewState.view !== 'home');
  document.getElementById('view-targets').classList.toggle('hidden', state.viewState.view !== 'profiles');
  document.getElementById('view-discoveries').classList.toggle('hidden', state.viewState.view !== 'findings');
  NAV_VIEWS.forEach(name => {
    const button = document.getElementById(`nav-btn-${name}`);
    button.className = name === state.viewState.view ? NAV_TAB_ACTIVE : NAV_TAB_INACTIVE;
    if (name === state.viewState.view) button.setAttribute('aria-current', 'page');else button.removeAttribute('aria-current');
  });
  writeViewState();
  if (state.viewState.view === 'home') loadHomeOverview();
  if (state.viewState.view === 'findings' && loadFindings) {
    const select = document.getElementById('select-profile');
    if (!state.viewState.profile && select.options.length > 0) {
      select.value = select.options[0].value;
      onProfileChanged();
    } else if (state.viewState.profile && !state.currentRows.length) {
      loadCurrentView();
    }
  }
}
export function onProfileChanged() {
  const select = document.getElementById('select-profile');
  state.viewState.profile = UUID_RE.test(select.value) ? select.value : null;
  // A different target means a different set of rows, so the page, the node and
  // the filter all stop meaning anything.
  state.viewState.node = null;
  state.viewState.page = 1;
  state.viewState.filter = null;
  resetFilterPills();
  state.pendingNewFindings = {};
  state.severitySummaryCache = new Map();
  hideSeverityTooltip();
  renderNewFindingsBadge();
  loadCurrentView();
}

// Deletion is fire-and-confirm-by-notification: the browser confirm()/alert()
// dialogs were replaced by the app's own feedback path. Success is announced by
// the server's "profile deleted" notification over SSE (toast + bell counter),
// exactly as forceScan relies on the engine's "scan started" notification, so
// nothing is shown here on success. Only the failure toast is raised locally.

// resetFilterPills paints every pill inactive, then highlights the active one.
// Both this and the filter reset elsewhere go through PILL_* so the two can
// never drift apart again.
export function resetFilterPills(active = null) {
  document.querySelectorAll('.filter-pill').forEach(b => {
    b.className = `${PILL_BASE} ${PILL_INACTIVE}`;
    b.setAttribute('aria-pressed', String(b.id === `filter-btn-${active}`));
  });
  const chosen = active ? document.getElementById(`filter-btn-${active}`) : null;
  if (chosen) chosen.className = `${PILL_BASE} ${PILL_ACTIVE}`;
  document.getElementById('mobile-filter-summary').textContent = chosen ? `Filter · ${chosen.textContent.trim()}` : 'Filters · All nodes';
}
export function toggleFilter(filter) {
  state.viewState.filter = state.viewState.filter === filter ? null : filter;
  resetFilterPills(state.viewState.filter);
  // A filter changes which rows exist, so the page number it was on is
  // meaningless against the new set.
  state.viewState.page = 1;
  loadCurrentView();
}
export function onSortChanged() {
  const sort = document.getElementById('select-sort').value;
  state.viewState.sort = SORTS.includes(sort) ? sort : 'name-asc';
  state.viewState.page = 1;
  loadCurrentView();
}
export function onPageSizeChanged() {
  const size = parseInt(document.getElementById('select-size').value, 10);
  state.viewState.size = PAGE_SIZES.includes(size) ? size : defaultSizeForView();
  // Keep the first row of the current page visible rather than jumping to the
  // top: growing the page from 25 to 250 should widen the window, not move it.
  const firstRow = (state.viewState.page - 1) * state.pageMeta.size;
  state.viewState.page = Math.floor(firstRow / state.viewState.size) + 1;
  loadCurrentView();
}
export function goToPage(page) {
  const target = Math.min(Math.max(page, 1), Math.max(state.pageMeta.total_pages, 1));
  if (target === state.viewState.page) return;
  state.viewState.page = target;
  loadCurrentView();
}
export function reloadCurrentPage() {
  state.pendingNewFindings = {};
  state.severitySummaryCache = new Map();
  hideSeverityTooltip();
  renderNewFindingsBadge();
  loadCurrentView();
}

// ---------------------------------------------------------------- row builders

// The server stops counting a node's findings at COUNT_CAP, because the count is
// O(matching rows) and one host with tens of thousands of directories made its own
// page an order of magnitude slower than its neighbours. The badge only has to say
// "a lot"; the exact total is on the node's own tab, where it is still exact.
//
// This must match countCap in internal/api/subdomains.go.

// ---------------------------------------------------------------- navigation
export function switchDiscTab(tab, load = true) {
  state.viewState.tab = TABS.includes(tab) ? tab : 'subs';
  state.viewState.node = null;
  state.viewState.page = 1;
  state.viewState.size = defaultSizeForView();
  const btnS = document.getElementById('disc-tab-subs');
  const btnC = document.getElementById('disc-tab-secs');
  btnS.className = btnC.className = 'chroma-tab';
  btnS.setAttribute('aria-selected', String(state.viewState.tab === 'subs'));
  btnC.setAttribute('aria-selected', String(state.viewState.tab === 'secs'));
  syncSizeSelect();
  if (load) loadCurrentView();
}
export function openSubDashboard(host, label) {
  state.viewState.node = host;
  state.viewState.nodeTab = 'vulns';
  state.viewState.assessment = 'all';
  state.viewState.page = 1;
  state.viewState.size = defaultSizeForView();
  state.viewState.filter = null;
  resetFilterPills();
  syncSizeSelect();
  loadNodeAddresses();
  loadCurrentView();
}
export function closeSubDashboard() {
  state.viewState.node = null;
  state.viewState.page = 1;
  state.viewState.size = defaultSizeForView();
  setSubDashboardOpen(false);
  syncSizeSelect();
  loadCurrentView();
}

// switchSubDashboardTab paints the tab strip, and by default also loads the tab.
// Each tab is its own paginated request, so a node with 40000 directories costs the
// same as one with three until that tab is actually opened.
export function switchSubDashboardTab(tab, load = true) {
  state.viewState.nodeTab = SUB_TABS.includes(tab) ? tab : 'vulns';
  SUB_TABS.forEach(t => {
    const button = document.getElementById(`sub-tab-${t}`);
    button.className = 'chroma-tab';
    button.setAttribute('aria-selected', String(t === state.viewState.nodeTab));
    const content = document.getElementById(`sub-content-${t}`);
    content.classList.toggle('hidden', t !== state.viewState.nodeTab);
    content.classList.toggle('block', t === state.viewState.nodeTab);
  });
  if (load) {
    state.viewState.page = 1;
    state.viewState.size = defaultSizeForView();
    syncSizeSelect();
    loadCurrentView();
  }
}
export function syncSizeSelect() {
  const select = document.getElementById('select-size');
  const size = state.viewState.size;
  // A size that came from a hand-edited URL may not be one of the offered
  // options; show the nearest rather than silently resetting the view.
  const nearest = PAGE_SIZES.reduce((best, v) => Math.abs(v - size) < Math.abs(best - size) ? v : best, PAGE_SIZES[0]);
  select.value = String(PAGE_SIZES.includes(size) ? size : nearest);
}
// toggleTheme flips the attribute the whole palette hangs off and persists the
// choice. The inline <head> script reapplies it on the next load; without the
// stored value a reload would fall back to the OS preference and appear to
// forget what the operator picked.
export function toggleTheme() {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem('icevirtue-theme', next);
  } catch (e) {
    // Private mode: the theme still applies, it just will not survive a reload.
    console.warn('Could not persist the theme preference:', e);
  }
}
