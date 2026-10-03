// Events: live audit stream with filters, decision trace drawer and exports.
import { api, streamEvents, downloadExport } from '../api.js';
import { renderTrace, bindCopy } from '../trace.js';
import {
  html, timeEl, actionPill, topFinding, findingId, fmtMs, principalLabel, errorBox, emptyRow, ACTIONS, ACTION_LABEL,
} from '../util.js';

const ROUTES = ['openai.chat', 'mcp.call', 'mcp.list', 'guard.check', 'admin'];
const FILTER_KEYS = ['action', 'control', 'principal', 'route', 'q'];
const MAX_ROWS = 1000;

function matches(e, f) {
  if (f.action && e.action !== f.action) return false;
  if (f.route && e.route !== f.route) return false;
  if (f.principal && (!e.principal || e.principal.id !== f.principal)) return false;
  if (f.control && !(e.findings || []).some((x) => x.control === f.control)) return false;
  if (f.q) {
    const hay = [e.trace_id, e.session_id, e.excerpt, e.message, e.model, e.tool && e.tool.name, ...(e.findings || []).map(findingId)].join(' ').toLowerCase();
    if (!hay.includes(f.q.toLowerCase())) return false;
  }
  return true;
}

function row(e, { fresh = false, selected = false } = {}) {
  const sys = e.type && e.type !== 'decision';
  const f = topFinding(e);
  const lat = e.latency_ms || {};
  const more = (e.findings || []).length - 1;
  return html`<tr class="clickable ${fresh ? 'fresh' : ''} ${selected ? 'selected' : ''} ${sys ? 'row-sys' : ''}" data-trace="${e.trace_id}" tabindex="0">
    <td class="nowrap">${timeEl(e.ts)}</td>
    <td class="clip" title="${e.principal && e.principal.id ? `${e.principal.id} (team ${e.principal.team || '–'})` : ''}">${sys ? html`<span class="muted">system</span>` : principalLabel(e.principal)}</td>
    <td class="nowrap mono">${e.route || '–'}${e.tool && e.tool.name ? html`<div class="hint clip" title="${e.tool.name}">${e.tool.name}</div>` : ''}</td>
    <td class="nowrap">${sys ? e.type : e.direction || '–'}</td>
    <td class="clip" title="${e.model || ''}">${e.model || html`<span class="muted">–</span>`}</td>
    <td class="nowrap">${actionPill(e.action)}${e.enforced === false ? html` <span class="pill pill-outline" title="monitor mode: not enforced">monitor</span>` : ''}</td>
    <td class="cell-ellipsis" title="${f ? `${findingId(f)}: ${f.reason || ''}` : sys ? e.message || '' : ''}">${f ? html`<span class="mono">${findingId(f)}</span>${more > 0 ? html` <span class="muted">+${more}</span>` : ''}` : sys ? html`<span class="muted">${e.message || ''}</span>` : html`<span class="muted">–</span>`}</td>
    <td class="num nowrap">${sys ? '' : fmtMs(lat.gateway_overhead)}</td>
    <td class="num nowrap">${sys ? '' : fmtMs(lat.total)}</td>
  </tr>`;
}

export default {
  title: 'Events',
  mount(el, ctx) {
    const st = {
      filter: Object.fromEntries(FILTER_KEYS.map((k) => [k, ctx.query.get(k) || ''])),
      events: [],
      next: null,
      live: 'connecting',
      paused: false,
      pending: [],
      error: null,
      controls: [],
      open: ctx.params[0] || null,
      newCount: 0,
    };
    let stopStream = null;
    let alive = true;

    el.innerHTML = String(html`
      <div class="view-head">
        <h1>Events</h1>
        <span class="sub">Every decision is one audit event; click a row for the full decision trace.</span>
        <span class="spacer"></span>
        <span class="live" id="live"><span class="live-dot"></span><span class="live-text">connecting</span></span>
        <button type="button" class="btn" id="pause">Pause</button>
        <button type="button" class="btn" data-export="jsonl" title="Download the audit log as JSON Lines, filtered like the table">Export JSONL</button>
        <button type="button" class="btn" data-export="csv" title="Download the audit log as CSV, filtered like the table">Export CSV</button>
      </div>
      <form class="toolbar" id="filters" autocomplete="off">
        <label class="field"><span>Action</span><select name="action"><option value="">any</option>${ACTIONS.map((a) => html`<option value="${a}">${ACTION_LABEL[a]}</option>`)}</select></label>
        <label class="field"><span>Control</span><select name="control"><option value="">any</option></select></label>
        <label class="field"><span>Principal</span><select name="principal"><option value="">any</option></select></label>
        <label class="field"><span>Route</span><select name="route"><option value="">any</option>${ROUTES.map((r) => html`<option value="${r}">${r}</option>`)}</select></label>
        <label class="field" style="flex:1 1 220px"><span>Search</span><input type="search" name="q" placeholder="trace id, session, finding id, excerpt text"></label>
        <button type="submit" class="btn btn-primary">Apply</button>
        <button type="button" class="btn" id="clear">Clear</button>
      </form>
      <div id="msg"></div>
      <div class="card" style="padding:0">
        <div class="table-wrap"><table class="tbl" id="tbl">
          <thead><tr><th>Time</th><th>Principal</th><th>Route</th><th>Direction</th><th>Model</th><th>Action</th><th>Top finding</th><th class="num" title="Time added by Bouncer (T0+T1+T2+processing)">Overhead</th><th class="num" title="Overhead plus upstream time">Total</th></tr></thead>
          <tbody id="rows"><tr class="empty"><td colspan="9">Loading events...</td></tr></tbody>
        </table></div>
      </div>
      <div class="row-flex" style="margin-top:10px"><span class="hint" id="count"></span><span class="spacer"></span><button type="button" class="btn" id="older" hidden>Load older</button></div>
      <div id="drawer-root"></div>`);

    const $ = (s) => el.querySelector(s);
    const form = $('#filters');
    bindCopy(el);

    const syncForm = () => { for (const k of FILTER_KEYS) form.elements[k].value = st.filter[k] || ''; };
    const fillSelect = (name, values) => {
      const sel = form.elements[name];
      const cur = st.filter[name];
      sel.innerHTML = '<option value="">any</option>' + values.map((v) => String(html`<option value="${v}">${v}</option>`)).join('');
      if (cur && !values.includes(cur)) sel.insertAdjacentHTML('beforeend', String(html`<option value="${cur}">${cur}</option>`));
      sel.value = cur || '';
    };
    const fillPrincipals = (p) => fillSelect('principal', ((p && p.principals) || []).map((x) => x.id));
    fillPrincipals(ctx.app.policy);
    const offPolicy = ctx.app.onPolicy(fillPrincipals);
    api('/api/controls').then((d) => { st.controls = (d.controls || []).map((c) => c.id); fillSelect('control', st.controls); }).catch(() => fillSelect('control', []));
    syncForm();

    const filterQuery = () => Object.fromEntries(Object.entries(st.filter).filter(([, v]) => v));
    const hashFor = (trace) => {
      const q = new URLSearchParams(filterQuery()).toString();
      return '#/events' + (trace ? '/' + encodeURIComponent(trace) : '') + (q ? '?' + q : '');
    };

    const renderRows = () => {
      const tbody = $('#rows');
      if (st.error) { tbody.innerHTML = String(emptyRow(9, 'Could not load events.')); return; }
      if (!st.events.length) {
        const any = Object.values(st.filter).some(Boolean);
        tbody.innerHTML = String(emptyRow(9, any ? 'No events match this filter.' : 'No events yet. Send a request through the gateway or use the Playground.'));
      } else {
        tbody.innerHTML = st.events.map((e) => String(row(e, { fresh: e.__fresh, selected: e.trace_id === st.open }))).join('');
        st.events.forEach((e) => { delete e.__fresh; });
      }
      $('#count').textContent = `${st.events.length} event${st.events.length === 1 ? '' : 's'} shown${st.newCount ? `, ${st.newCount} received live` : ''}${st.paused && st.pending.length ? `, ${st.pending.length} waiting (paused)` : ''}`;
      $('#older').hidden = !st.next;
    };

    const setLive = (s, delay, reason) => {
      st.live = s;
      const live = $('#live');
      live.className = 'live live-' + (st.paused ? 'paused' : s);
      live.querySelector('.live-text').textContent = st.paused ? 'paused' : s === 'live' ? 'live' : s === 'disconnected' ? `disconnected, retry in ${Math.round(delay / 1000)} s` : 'connecting';
      live.title = reason || '';
    };

    const load = async (append = false) => {
      try {
        const d = await api('/api/events', { query: { ...filterQuery(), limit: 200, before_seq: append ? st.next : undefined } });
        if (!alive) return;
        st.error = null;
        $('#msg').innerHTML = '';
        st.events = append ? st.events.concat(d.events || []) : d.events || [];
        st.next = d.next_before_seq || null;
      } catch (e) {
        st.error = e;
        $('#msg').innerHTML = String(errorBox(e, 'GET /api/events'));
      }
      renderRows();
    };

    const onEvent = (e) => {
      if (!matches(e, st.filter)) return;
      if (st.events.some((x) => x.seq === e.seq && x.trace_id === e.trace_id)) return;
      if (st.paused) { st.pending.unshift(e); renderRows(); return; }
      e.__fresh = true;
      st.newCount += 1;
      st.events.unshift(e);
      if (st.events.length > MAX_ROWS) st.events.length = MAX_ROWS;
      renderRows();
      if (st.open && e.trace_id === st.open) openDrawer(st.open);
    };

    // ---------------------------------------------------------- drawer
    const closeDrawer = () => { $('#drawer-root').innerHTML = ''; };
    const openDrawer = async (trace) => {
      const root = $('#drawer-root');
      root.innerHTML = String(html`<div class="drawer-backdrop" data-close></div>
        <aside class="drawer" role="dialog" aria-label="Decision trace">
          <div class="drawer-head"><h2>Decision trace</h2><span class="spacer"></span>
            <a class="btn btn-small" href="${hashFor(trace)}" title="Link to this trace">Permalink</a>
            <button type="button" class="btn" data-close>Close (Esc)</button></div>
          <div class="drawer-body"><p class="loading">Loading trace ${trace}...</p></div>
        </aside>`);
      try {
        const t = await api('/api/events/' + encodeURIComponent(trace));
        if (!alive || st.open !== trace) return;
        root.querySelector('.drawer-body').innerHTML = String(renderTrace(t));
      } catch (e) {
        root.querySelector('.drawer-body').innerHTML = String(errorBox(e, `GET /api/events/${trace}`));
      }
    };

    el.addEventListener('click', (e) => {
      if (e.target.closest('[data-close]')) { location.hash = hashFor(null); return; }
      const ex = e.target.closest('[data-export]');
      if (ex) {
        ex.disabled = true;
        downloadExport(ex.dataset.export, filterQuery())
          .catch((err) => { $('#msg').innerHTML = String(errorBox(err, `Export ${ex.dataset.export}`)); })
          .finally(() => { ex.disabled = false; });
        return;
      }
      const tr = e.target.closest('tr[data-trace]');
      if (tr && !e.target.closest('a')) location.hash = hashFor(tr.dataset.trace);
    });
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const tr = e.target.closest('tr[data-trace]');
        if (tr) location.hash = hashFor(tr.dataset.trace);
      }
    });
    const onKey = (e) => { if (e.key === 'Escape' && st.open && !document.querySelector('dialog[open]')) location.hash = hashFor(null); };
    document.addEventListener('keydown', onKey);

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      for (const k of FILTER_KEYS) st.filter[k] = (form.elements[k].value || '').trim();
      location.hash = hashFor(st.open);
      st.newCount = 0;
      load();
    });
    form.addEventListener('change', (e) => { if (e.target.tagName === 'SELECT') form.requestSubmit(); });
    $('#clear').addEventListener('click', () => { FILTER_KEYS.forEach((k) => { st.filter[k] = ''; }); syncForm(); form.requestSubmit(); });
    $('#older').addEventListener('click', () => load(true));
    $('#pause').addEventListener('click', () => {
      st.paused = !st.paused;
      $('#pause').textContent = st.paused ? 'Resume' : 'Pause';
      if (!st.paused && st.pending.length) {
        st.pending.forEach((x) => { x.__fresh = true; });
        st.newCount += st.pending.length;
        st.events = st.pending.concat(st.events).slice(0, MAX_ROWS);
        st.pending = [];
        renderRows();
      }
      setLive(st.live, 0);
    });

    load().then(() => { if (st.open) openDrawer(st.open); });
    stopStream = streamEvents({ onEvent, onStatus: setLive });

    this._update = (c) => {
      const nextFilter = Object.fromEntries(FILTER_KEYS.map((k) => [k, c.query.get(k) || '']));
      const filterChanged = FILTER_KEYS.some((k) => nextFilter[k] !== st.filter[k]);
      st.open = c.params[0] || null;
      if (filterChanged) { st.filter = nextFilter; syncForm(); load(); }
      el.querySelectorAll('tr[data-trace]').forEach((r) => r.classList.toggle('selected', r.dataset.trace === st.open));
      if (st.open) openDrawer(st.open); else closeDrawer();
    };
    return () => { alive = false; if (stopStream) stopStream(); offPolicy(); document.removeEventListener('keydown', onKey); this._update = null; };
  },
  update(ctx) { if (this._update) this._update(ctx); },
};
