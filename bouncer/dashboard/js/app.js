// App shell: router, header (policy chip, theme, time zone, admin token), reload-failure banner.
import { api, FIXTURES, getToken, setToken } from './api.js';
import { initTooltip } from './charts.js';
import { settings, store, shortHash, esc } from './util.js';
import { reloadFailureBanner } from './banner.js';
import overview from './views/overview.js';
import events from './views/events.js';
import controls from './views/controls.js';
import coverage from './views/coverage.js';
import playground from './views/playground.js';
import approvals from './views/approvals.js';
import performance from './views/performance.js';
import policy from './views/policy.js';
import signatures from './views/signatures.js';

const VIEWS = { overview, events, controls, coverage, playground, approvals, performance, policy, signatures };

export const app = {
  policy: null,
  policyError: null,
  listeners: new Set(),
  onPolicy(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); },
  async refreshPolicy() {
    try {
      this.policy = await api('/api/policy');
      this.policyError = null;
    } catch (e) {
      this.policyError = e;
    }
    renderHeader();
    renderBanner();
    this.listeners.forEach((fn) => fn(this.policy));
    return this.policy;
  },
  async refreshApprovals() {
    try {
      const d = await api('/api/approvals');
      const n = (d.approvals || []).filter((a) => a.status === 'pending').length;
      const el = document.getElementById('nav-approvals');
      el.hidden = n === 0;
      el.textContent = String(n);
      el.title = `${n} pending approval${n === 1 ? '' : 's'}`;
    } catch (_) { /* shown in the Approvals view */ }
  },
};

// ---------------------------------------------------------------- header
function renderHeader() {
  const chip = document.getElementById('policy-chip');
  const p = app.policy;
  chip.classList.remove('chip-bad', 'chip-warn');
  if (!p) {
    chip.textContent = app.policyError ? 'policy unavailable' : 'policy –';
    if (app.policyError) { chip.classList.add('chip-bad'); chip.title = app.policyError.message; }
    return;
  }
  const failed = p.reload && p.reload.status === 'failed';
  chip.textContent = `policy ${shortHash(p.version)} · ${p.profile} · ${p.mode}${failed ? ' · last reload failed' : ''}`;
  chip.title = `Active policy ${p.version}\nprofile ${p.profile}, mode ${p.mode}, fail_mode ${p.fail_mode}\nloaded ${p.loaded_at}`;
  if (failed) chip.classList.add('chip-bad');
  else if (p.mode === 'monitor') chip.classList.add('chip-warn');
}

function renderBanner() {
  const el = document.getElementById('banner');
  const p = app.policy;
  if (!p || !p.reload || p.reload.status !== 'failed') { el.innerHTML = ''; return; }
  el.innerHTML = String(reloadFailureBanner(p));
}

function initHeader() {
  if (FIXTURES) {
    const b = document.getElementById('fixture-badge');
    b.hidden = false;
    b.textContent = FIXTURES === 'default' ? 'Fixture data, not live' : `Fixture data (${FIXTURES}), not live`;
    b.title = 'The dashboard is reading bouncer/dashboard/fixtures/*.json instead of the gateway API. Remove ?fixtures from the URL for live data.';
    document.title = 'Bouncer Dashboard (fixture data)';
  }
  // theme
  const themeBtn = document.getElementById('theme-btn');
  const isDark = () => {
    const t = document.documentElement.getAttribute('data-theme');
    if (t) return t === 'dark';
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  };
  const syncTheme = () => { themeBtn.textContent = isDark() ? 'Light' : 'Dark'; };
  themeBtn.addEventListener('click', () => {
    const next = isDark() ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    store.set('theme', next);
    syncTheme();
  });
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', syncTheme);
  syncTheme();
  // time zone
  const tzBtns = document.querySelectorAll('[data-tz]');
  const syncTz = () => tzBtns.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.tz === settings.tz)));
  tzBtns.forEach((b) => b.addEventListener('click', () => { settings.tz = b.dataset.tz; syncTz(); route(true); }));
  syncTz();
  // clock
  const clock = document.getElementById('clock');
  const tick = () => {
    const d = new Date();
    const utc = settings.tz === 'utc';
    const p = (n) => String(n).padStart(2, '0');
    clock.textContent = utc ? `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC`
      : `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())} local`;
  };
  tick();
  setInterval(tick, 1000);
  // admin token
  const tokenBtn = document.getElementById('token-btn');
  const dlg = document.getElementById('token-dialog');
  dlg.querySelector('[data-cancel]').addEventListener('click', () => dlg.close('cancel'));
  const syncToken = () => { tokenBtn.textContent = getToken() ? 'Admin token: set' : 'Admin token'; };
  tokenBtn.addEventListener('click', () => {
    if (getToken() && window.confirm('Remove the stored admin token from this browser?')) { setToken(null); syncToken(); return; }
    dlg.querySelector('.token-reason').textContent = 'Needed only when the gateway is started with BOUNCER_ADMIN_TOKEN.';
    dlg.querySelector('input').value = '';
    const onClose = () => {
      dlg.removeEventListener('close', onClose);
      if (dlg.returnValue === 'ok' && dlg.querySelector('input').value.trim()) { setToken(dlg.querySelector('input').value.trim()); route(true); }
      syncToken();
    };
    dlg.addEventListener('close', onClose);
    dlg.showModal();
  });
  dlg.addEventListener('close', syncToken);
  syncToken();
  // The report sits behind the same admin token: with a token set, fetch it with the header and open the HTML.
  document.getElementById('report-link').addEventListener('click', async (e) => {
    if (!getToken() || FIXTURES) return;
    e.preventDefault();
    const win = window.open('', '_blank');
    try {
      const res = await fetch('/reports/summary', { headers: { Authorization: 'Bearer ' + getToken() } });
      const text = await res.text();
      const url = URL.createObjectURL(new Blob([text], { type: res.headers.get('Content-Type') || 'text/html' }));
      if (win) win.location.href = url; else window.location.href = url;
    } catch (err) {
      if (win) win.close();
      window.alert('Could not load /reports/summary: ' + err.message);
    }
  });
}

// ---------------------------------------------------------------- router
let current = null; // { id, view, cleanup }

function parseHash() {
  const h = location.hash.replace(/^#\/?/, '');
  const [path, q = ''] = h.split('?');
  const segs = path.split('/').filter(Boolean).map(decodeURIComponent);
  return { id: VIEWS[segs[0]] ? segs[0] : 'overview', params: segs.slice(1), query: new URLSearchParams(q) };
}

function route(force = false) {
  const r = parseHash();
  document.querySelectorAll('[data-nav]').forEach((a) => {
    const on = a.dataset.nav === r.id;
    a.classList.toggle('active', on);
    if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  });
  const ctx = { params: r.params, query: r.query, app };
  if (!force && current && current.id === r.id && current.view.update) {
    current.view.update(ctx);
    return;
  }
  if (current && current.cleanup) { try { current.cleanup(); } catch (_) { /* ignore */ } }
  const body = document.getElementById('view-body');
  const fresh = document.createElement('div');
  fresh.className = 'view view-' + r.id;
  body.replaceChildren(fresh);
  window.scrollTo(0, 0);
  const view = VIEWS[r.id];
  document.title = `${view.title} · Bouncer${FIXTURES ? ' (fixture data)' : ''}`;
  let cleanup = null;
  try { cleanup = view.mount(fresh, ctx); } catch (e) { fresh.innerHTML = `<div class="notice notice-error">View failed to render: ${esc(e.message)}</div>`; console.error(e); }
  current = { id: r.id, view, cleanup };
}

window.addEventListener('hashchange', () => route());
initTooltip();
initHeader();
if (!location.hash) history.replaceState(null, '', location.pathname + location.search + '#/overview');
route();
app.refreshPolicy();
app.refreshApprovals();
setInterval(() => app.refreshPolicy(), 15000);
setInterval(() => app.refreshApprovals(), 15000);
