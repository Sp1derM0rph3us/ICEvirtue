import { COUNT_CAP, ESCAPES } from './state.js';
// esc renders untrusted text into an HTML context.
//
// Almost nothing this dashboard displays is its own copy: a subdomain name
// comes from subfinder, a finding title from whoever wrote the nuclei
// template, a secret value out of somebody else's JavaScript. All of it is
// attacker-influenced, so none of it may reach innerHTML unescaped.
export function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ESCAPES[c]);
}

// safeURL keeps a tool-supplied URL out of an href unless it is http(s).
// Escaping the text is not enough on its own: "javascript:..." in an href
// is one click away from script execution. Relative and scheme-less values
// throw and are rejected, since a finding we cannot resolve is not a link
// we should offer.
export function safeURL(value) {
  try {
    const url = new URL(String(value ?? ''));
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : '#';
  } catch {
    return '#';
  }
}

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

// ---------------------------------------------------------------- row builders

// The server stops counting a node's findings at COUNT_CAP, because the count is
// O(matching rows) and one host with tens of thousands of directories made its own
// page an order of magnitude slower than its neighbours. The badge only has to say
// "a lot"; the exact total is on the node's own tab, where it is still exact.
//
// This must match countCap in internal/api/subdomains.go.
export function countLabel(n) {
  return n >= COUNT_CAP ? `${COUNT_CAP}+` : String(n);
}
export function severityClass(severity) {
  switch (severity) {
    case 'critical':
      return 'text-rose-500';
    case 'high':
      return 'text-orange-400';
    case 'medium':
      return 'text-amber-500';
    case 'low':
      return 'text-emerald-500';
    default:
      return 'text-slate-400';
  }
}
