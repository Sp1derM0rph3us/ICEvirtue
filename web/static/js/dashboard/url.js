import { DEFAULT_PROFILES_SIZE, DEFAULT_SIZE, FILTERS, MAX_PAGE_SIZE, NAV_VIEWS, PAGE_SIZES, SORTS, SUB_TABS, TABS, UUID_RE, state } from './state.js';

export
// readViewState validates every parameter it reads.
//
// These values come from whoever composed the link. profile is interpolated into a
// fetch path, so a non-UUID has to be dropped rather than passed through; size has
// to be clamped or a hand-edited URL could ask the server for more than it will
// give and leave the pager describing a page that was never served.
function readViewState() {
  const q = new URLSearchParams(location.search);
  const requestedView = q.get('view');
  const profile = q.get('profile');
  const homeProfile = q.get('home_profile');
  const tab = q.get('tab');
  const nodeTab = q.get('nodetab');
  const sort = q.get('sort');
  const filter = q.get('filter');
  const node = q.get('node');
  const clampInt = (raw, fallback, lo, hi) => {
    const n = parseInt(raw, 10);
    return Number.isFinite(n) ? Math.min(Math.max(n, lo), hi) : fallback;
  };
  state.viewState.profile = UUID_RE.test(profile || '') ? profile : null;
  state.viewState.homeProfile = UUID_RE.test(homeProfile || '') ? homeProfile : null;
  // Links from before top-level navigation state existed have no view. A
  // discovery context in one of those links must keep opening Findings rather
  // than silently landing on the new Home placeholder.
  state.viewState.view = NAV_VIEWS.includes(requestedView) ? requestedView : state.viewState.profile ? 'findings' : 'home';
  state.viewState.tab = TABS.includes(tab) ? tab : 'subs';
  state.viewState.nodeTab = SUB_TABS.includes(nodeTab) ? nodeTab : 'vulns';
  state.viewState.sort = SORTS.includes(sort) ? sort : 'name-asc';
  state.viewState.filter = FILTERS.includes(filter) ? filter : null;
  state.viewState.assessment = ['confirmed','unknown'].includes(q.get('assessment')) ? q.get('assessment') : 'all';
  // A node name is only ever compared and displayed, never used to build a path,
  // but it still reaches the DOM, so it goes through esc() at every use site.
  state.viewState.node = node && node.length <= 253 ? node : null;
  state.viewState.page = clampInt(q.get('page'), 1, 1, 1000000);
  state.viewState.size = clampInt(q.get('size'), defaultSizeForView(), 1, MAX_PAGE_SIZE);
  state.viewState.profilesPage = clampInt(q.get('profiles_page'), 1, 1, 1000000);
  const profilesSize = Number(q.get('profiles_size'));
  state.viewState.profilesSize = PAGE_SIZES.includes(profilesSize) ? profilesSize : DEFAULT_PROFILES_SIZE;
}

// writeViewState uses replaceState, not pushState: a filter click or a page step is
// not a navigation, and pushing would make the back button walk backwards through
// every pill the operator tried instead of leaving the app.
export function writeViewState() {
  const q = new URLSearchParams();
  // A plain root URL stays clean and opens Home. Once a Findings context is
  // present, write Home explicitly so returning there does not look like a
  // pre-navigation legacy link and reopen Findings on refresh.
  if (state.viewState.view !== 'home' || state.viewState.profile) q.set('view', state.viewState.view);
  if (state.viewState.profile) q.set('profile', state.viewState.profile);
  if (state.viewState.homeProfile) q.set('home_profile', state.viewState.homeProfile);
  if (state.viewState.tab !== 'subs') q.set('tab', state.viewState.tab);
  if (state.viewState.node) {
    q.set('node', state.viewState.node);
    if (state.viewState.nodeTab !== 'vulns') q.set('nodetab', state.viewState.nodeTab);
  }
  if (state.viewState.page > 1) q.set('page', String(state.viewState.page));
  if (state.viewState.size !== defaultSizeForView()) q.set('size', String(state.viewState.size));
  if (state.viewState.profilesPage > 1) q.set('profiles_page', String(state.viewState.profilesPage));
  if (state.viewState.profilesSize !== DEFAULT_PROFILES_SIZE) q.set('profiles_size', String(state.viewState.profilesSize));
  if (state.viewState.sort !== 'name-asc') q.set('sort', state.viewState.sort);
  if (state.viewState.filter) q.set('filter', state.viewState.filter);
  if (state.viewState.node && state.viewState.nodeTab === 'dirs' && state.viewState.assessment !== 'all') q.set('assessment', state.viewState.assessment);
  const search = q.toString();
  history.replaceState(null, '', search ? `?${search}` : location.pathname);
}

// Which list is on screen, and therefore which endpoint and default size apply.
export function activeView() {
  if (state.viewState.node) return state.viewState.nodeTab === 'dirs' ? 'dirs' : state.viewState.nodeTab === 'secs' ? 'nodesecs' : 'vulns';
  return state.viewState.tab === 'secs' ? 'secs' : 'subs';
}
export function defaultSizeForView() {
  return DEFAULT_SIZE[activeView()] ?? 100;
}
