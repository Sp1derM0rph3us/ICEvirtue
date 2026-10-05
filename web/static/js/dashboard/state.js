

export const state = {};
export const CAN_WRITE = document.body.dataset.canWrite === 'true';
export const ESCAPES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
};

// The server clamps size to this. Offering more in the selector would show the
// operator a number the server silently refuses.
export const MAX_PAGE_SIZE = 1000;
export const PAGE_SIZES = [25, 50, 100, 250, 500];
export const DEFAULT_PROFILES_SIZE = 25;

// Per-tab defaults, matching the server's. They differ because the rows differ in
// width: a vulnerability carries a name and a severity, a directory is one line.
export const DEFAULT_SIZE = {
  subs: 100,
  secs: 50,
  vulns: 50,
  dirs: 100,
  nodesecs: 50
};

// Allow-lists for everything that arrives in the query string. Values from a URL
// are exactly as untrusted as a subfinder result -- somebody sends you a link --
// and profile in particular is interpolated into a fetch path, so a crafted value
// would otherwise choose which endpoint gets called.
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const NAV_VIEWS = ['home', 'profiles', 'findings'];
export const TABS = ['subs', 'secs'];
export const SUB_TABS = ['vulns', 'dirs', 'secs'];
export const SORTS = ['name-asc', 'name-desc', 'findings-desc', 'findings-asc', 'first-asc', 'first-desc', 'update-asc', 'update-desc'];
export const FILTERS = ['ip', 'subdomain', 'vuln-critical', 'vuln-info', 'secrets', 'status-2xx-3xx', 'status-403', 'status-other', 'updated'];

// A request that has not answered in this long has stopped being useful. There was
// no timeout at all before -- not in the browser and not on the server, where
// ListenAndServe leaves every deadline at zero -- so a stalled request simply hung
// with the fixed string "Failed to fetch discoveries." as the only feedback.
export const REQUEST_TIMEOUT_MS = 60000;

// The filter pills' class strings live here because two different functions
// used to write them from memory and had drifted apart in eleven places:
// openSubDashboard reset them to small, pill-shaped, lowercase, grey buttons
// with no neon hover, so returning from a node sub-dashboard silently
// reskinned the whole filter bar until the next click or a page reload.
export const PILL_BASE = 'filter-pill chroma-filter-pill';
export const PILL_INACTIVE = '';
export const PILL_ACTIVE = '';

// Same reason: switchView reassigned these wholesale and dropped
// hover:text-accent and transition-all from the markup's own classes.
export const NAV_TAB_ACTIVE = 'chroma-nav-tab tab-active';
export const NAV_TAB_INACTIVE = 'chroma-nav-tab tab-inactive';

// viewState is the single description of what the operator is looking at, and it
// round-trips through the query string so a refresh, a bookmark or a shared link
// lands on the same page. Everything in it has been validated by readViewState.
state.viewState = {
  view: 'home',
  // selected top-level navigation view
  homeProfile: null,
  // independent of the Findings profile and node context
  profile: null,
  tab: 'subs',
  // which top-level Findings tab
  node: null,
  // the sub-dashboard's host, or null
  nodeTab: 'vulns',
  // which sub-dashboard tab
  profilesPage: 1,
  profilesSize: DEFAULT_PROFILES_SIZE,
  page: 1,
  size: DEFAULT_SIZE.subs,
  sort: 'name-asc',
  filter: null
};
state.pageMeta = {
  page: 1,
  size: DEFAULT_SIZE.subs,
  total_rows: 0,
  total_pages: 1
};
state.scheduleTrigger = null;
state.currentRows = [];
state.profileRows = [];
state.profilePageMeta = {
  page: 1,
  size: DEFAULT_PROFILES_SIZE,
  total_rows: 0,
  total_pages: 1
};
state.profilePageRequest = 0;
state.profilePageLoading = false;
state.profilePageError = false;
export const mobileLayout = window.matchMedia('(max-width: 640px)');

// Counts accumulated from SSE while a scan runs, shown as a badge rather than
// acted on. The old handler refetched the whole profile eight seconds after each
// event, which is what made reading a table during a scan impossible.
state.pendingNewFindings = {};
export
// Severity summaries are fetched only after intentful hover and cached for
// the current profile. A list page remains one lightweight request.
const SEVERITY_TOOLTIP_DELAY = 200;
state.severitySummaryCache = new Map();
state.severityTooltipTimer = null;
state.severityTooltipBadge = null;
state.severityTooltipRequest = 0;
state.inFlight = null;
state.homeOverviewRequest = 0;
state.nodeInfoRequest = 0;
state.profileIndexReady = false;
export const HOME_SEVERITY_COLORS = {
  critical: 'var(--ui-coral)',
  high: 'var(--ui-amber)',
  medium: 'var(--sev-medium)',
  low: 'var(--ui-teal)',
  info: 'var(--ui-blue)',
  unknown: 'var(--ui-muted)'
};
export
// goToLogin leaves for the login page.
//
// The EventSource is closed first: per the spec an HTTP error status fails the
// connection permanently, so leaving it open would have it retry, take another 401
// and shut down for good while the page still looked connected.
//
// The return position is kept in sessionStorage and never sent to the server. A
// ?next= parameter would be an open redirect, and every hand-rolled validator for
// one is a step away from accepting //evil.com; here the only thing ever appended
// to "/" is something proved to be a query string.
const RETURN_KEY = 'icevirtue-return';
export const SAFE_QUERY = /^\?[^/\\:#]*$/;
state.leaving = false;
export
// ---------------------------------------------------------------- row builders

// The server stops counting a node's findings at COUNT_CAP, because the count is
// O(matching rows) and one host with tens of thousands of directories made its own
// page an order of magnitude slower than its neighbours. The badge only has to say
// "a lot"; the exact total is on the node's own tab, where it is still exact.
//
// This must match countCap in internal/api/subdomains.go.
const COUNT_CAP = 1000;
export
// ---- Notifications & toasts ----
const NOTIF_STYLE = {
  scan_started: {
    cls: 'ok',
    icon: 'check'
  },
  scan_finished: {
    cls: 'ok',
    icon: 'check'
  },
  scan_halted: {
    cls: 'crit',
    icon: 'alert'
  },
  credentials: {
    cls: 'info',
    icon: 'key'
  }
};
export const NOTIF_ICONS = {
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
  alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>',
  key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.5 12.5 7-7M17 3l3 3-3 3"/></svg>'
};
state.notifItems = [];
state.notifUnread = 0;
