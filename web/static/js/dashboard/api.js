import { REQUEST_TIMEOUT_MS, RETURN_KEY, state } from './state.js';

export
// api is the only way this page talks to the server.
//
// It carries the timeout that did not exist before, and it names what failed. The
// previous code surfaced every failure as the same fixed string, with the actual
// status only reaching console.error.
async function api(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(path, {
      credentials: 'same-origin',
      signal: controller.signal,
      ...options
    });
    if (res.status === 401) {
      // Every caller's correct reaction to a dead session is the same, so it
      // is handled once here. Without this an expired session left the
      // dashboard looking alive while every button failed silently.
      goToLogin();
      throw new Error('session expired');
    }
    if (!res.ok) {
      const detail = (await res.text().catch(() => '')).trim();
      throw new Error(`${res.status} ${res.statusText}${detail ? ': ' + detail : ''}`);
    }
    return res;
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error(`timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

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
export function goToLogin() {
  if (state.leaving) return;
  state.leaving = true;
  try {
    if (typeof sse !== 'undefined' && sse) sse.close();
  } catch (e) {}
  try {
    sessionStorage.setItem(RETURN_KEY, location.search);
  } catch (e) {}
  window.location.replace('/login');
}
export async function apiJSON(path, options = {}) {
  return (await api(path, options)).json();
}

// readViewState validates every parameter it reads.
//
// These values come from whoever composed the link. profile is interpolated into a
// fetch path, so a non-UUID has to be dropped rather than passed through; size has
// to be clamped or a hand-edited URL could ask the server for more than it will
// give and leave the pager describing a page that was never served.
export async function logout() {
  try {
    await fetch('/api/logout', {
      method: 'POST',
      credentials: 'same-origin'
    });
    // /login directly, rather than reloading / and taking the redirect.
    window.location.replace('/login');
  } catch (err) {
    console.error("Logout failed:", err);
  }
}

// One delegated listener per generated table, replacing the inline onclick
// handlers those rows used to carry. Registered on the tbody rather than the
// rows, so it survives the innerHTML='' that every re-render does.
