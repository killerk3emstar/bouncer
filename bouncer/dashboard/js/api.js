// API client: JSON calls, admin token handling, SSE over fetch, exports, and fixture mode.
// Fixture mode: open the page with ?fixtures=1 (default set), ?fixtures=empty or ?fixtures=failed.
import { store, findingId, topFinding } from './util.js';

const params = new URLSearchParams(location.search);
const fx = params.get('fixtures');
export const FIXTURES = fx && fx !== '0' && fx !== 'false' ? (fx === '1' || fx === 'true' ? 'default' : fx.replace(/[^a-z0-9_-]/gi, '')) : null;

export class ApiError extends Error {
  constructor(status, message, body) { super(message); this.status = status; this.body = body; }
}

// ---------------------------------------------------------------- admin token
const TOKEN_KEY = 'adminToken';
export const getToken = () => store.get(TOKEN_KEY);
export const setToken = (t) => store.set(TOKEN_KEY, t || null);

// `make dev` prints /ui/?token=...: store the token and remove it from the address bar and history.
{
  const urlToken = new URLSearchParams(location.search).get('token');
  if (urlToken) {
    setToken(urlToken);
    const clean = new URL(location.href);
    clean.searchParams.delete('token');
    history.replaceState(null, '', clean.pathname + clean.search + clean.hash);
  }
}

let tokenPrompt = null;
// Asks for the admin token once, even when several requests get 401 at the same time.
export function promptToken(reason) {
  if (tokenPrompt) return tokenPrompt;
  tokenPrompt = new Promise((resolve, reject) => {
    const dlg = document.getElementById('token-dialog');
    const input = dlg.querySelector('input');
    const msg = dlg.querySelector('.token-reason');
    msg.textContent = reason || 'The API returned 401 Unauthorized. Enter the admin token (BOUNCER_ADMIN_TOKEN) to continue.';
    input.value = '';
    const done = (ok) => {
      dlg.removeEventListener('close', onClose);
      tokenPrompt = null;
      if (ok && input.value.trim()) { setToken(input.value.trim()); resolve(); }
      else reject(new ApiError(401, 'Admin token required. Set it with the "Admin token" button in the header.'));
    };
    const onClose = () => done(dlg.returnValue === 'ok');
    dlg.addEventListener('close', onClose);
    dlg.showModal();
    input.focus();
  });
  return tokenPrompt;
}

function authHeaders(extra = {}) {
  const h = { ...extra };
  const t = getToken();
  if (t) h.Authorization = 'Bearer ' + t;
  return h;
}

function qs(query) {
  if (!query) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null && v !== '') p.set(k, v);
  const s = p.toString();
  return s ? '?' + s : '';
}

async function parseError(res) {
  let body = null;
  let message = res.statusText || 'Request failed';
  try {
    body = await res.json();
    if (body && body.error) message = body.error.message || body.error.code || message;
    else if (body && body.detail) message = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
  } catch (_) { /* not JSON */ }
  return new ApiError(res.status, message, body);
}

// ---------------------------------------------------------------- main entry
export async function api(path, { method = 'GET', query, body, retry = true } = {}) {
  if (FIXTURES) return fixtureRequest(method, path, query || {}, body);
  const headers = authHeaders({ Accept: 'application/json' });
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let res;
  try {
    res = await fetch(path + qs(query), { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  } catch (e) {
    throw new ApiError(0, `Gateway not reachable (${e.message}). Check that the gateway runs on this host.`);
  }
  if (res.status === 401 && retry) {
    await promptToken();
    return api(path, { method, query, body, retry: false });
  }
  if (!res.ok) throw await parseError(res);
  return res.json();
}

// ---------------------------------------------------------------- SSE (fetch-based, so the auth header works)
export function streamEvents({ onEvent, onStatus }) {
  if (FIXTURES) return fixtureStream({ onEvent, onStatus });
  let stopped = false;
  let ctrl = null;
  let delay = 1000;
  let timer = null;

  const handle = (chunk) => {
    const data = chunk.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, '')).join('\n');
    if (!data) return;
    try { onEvent(JSON.parse(data)); } catch (_) { /* malformed line: ignore */ }
  };

  async function connect() {
    if (stopped) return;
    ctrl = new AbortController();
    onStatus('connecting');
    try {
      const res = await fetch('/api/events/stream', { headers: authHeaders({ Accept: 'text/event-stream' }), signal: ctrl.signal, cache: 'no-store' });
      if (res.status === 401) { await promptToken(); return connect(); }
      if (!res.ok || !res.body) throw new Error('HTTP ' + res.status);
      onStatus('live');
      delay = 1000;
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf = (buf + value).replace(/\r\n?/g, '\n');
        const parts = buf.split('\n\n');
        buf = parts.pop();
        parts.forEach(handle);
      }
      throw new Error('stream closed by server');
    } catch (e) {
      if (stopped) return;
      onStatus('disconnected', delay, e.message);
      timer = setTimeout(connect, delay);
      delay = Math.min(delay * 2, 15000);
    }
  }
  connect();
  return () => { stopped = true; clearTimeout(timer); if (ctrl) ctrl.abort(); };
}

// ---------------------------------------------------------------- exports
export async function downloadExport(format, filter) {
  const name = `bouncer-audit-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.${format}`;
  let blob;
  if (FIXTURES) {
    const events = (await fixtureRequest('GET', '/api/events', { ...filter, limit: 100000 })).events.sort((a, b) => a.seq - b.seq);
    const text = format === 'csv' ? toCsv(events) : events.map((e) => JSON.stringify(e)).join('\n') + (events.length ? '\n' : '');
    blob = new Blob([text], { type: format === 'csv' ? 'text/csv' : 'application/x-ndjson' });
  } else {
    const res = await fetch(`/api/export/audit.${format}` + qs(filter), { headers: authHeaders() });
    if (res.status === 401) { await promptToken(); return downloadExport(format, filter); }
    if (!res.ok) throw await parseError(res);
    blob = await res.blob();
  }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

// Column order documented in docs/API.md (export section). Used by fixture mode only.
export const CSV_COLUMNS = ['ts', 'seq', 'trace_id', 'type', 'principal', 'team', 'session_id', 'route', 'direction', 'model', 'upstream', 'action',
  'enforced', 'status_code', 'top_finding', 'findings', 'owasp', 'judge_invoked', 'latency_total_ms', 'gateway_overhead_ms', 'cost_usd',
  'policy_version', 'approval_id', 'excerpt', 'prev_hash', 'hash'];

function toCsv(events) {
  const q = (v) => {
    const s = v === null || v === undefined ? '' : String(v);
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const rows = [CSV_COLUMNS.join(',')];
  for (const e of events) {
    const fs = e.findings || [];
    const owasp = [...new Set(fs.flatMap((f) => [...(f.owasp_llm || []), ...(f.owasp_agentic || [])]))];
    const top = topFinding(e);
    rows.push([
      e.ts, e.seq, e.trace_id, e.type, e.principal && e.principal.id, e.principal && e.principal.team, e.session_id, e.route, e.direction,
      e.model, e.upstream, e.action, e.enforced, e.status_code, top ? findingId(top) : '', fs.map(findingId).join(';'), owasp.join(';'),
      e.judge && e.judge.invoked, e.latency_ms && e.latency_ms.total, e.latency_ms && e.latency_ms.gateway_overhead, e.usage && e.usage.cost_usd,
      e.policy && e.policy.version, e.approval_id, e.excerpt, e.prev_hash, e.hash,
    ].map(q).join(','));
  }
  return rows.join('\r\n') + '\r\n';
}

// ================================================================ fixture mode
const FIXTURE_NOW = Date.parse('2026-10-04T05:30:00.000Z');
const SHIFT = Date.now() - FIXTURE_NOW; // re-base fixture timestamps so "expires in" and relative times look current
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const FIX_BASE = new URL('../fixtures/', import.meta.url);
const cache = new Map();
const streamed = []; // events emitted by the simulated stream, so their traces can be opened

const NO_SHIFT = new Set(['resets_at']); // calendar boundaries stay as written
const reviver = (k, v) => (typeof v === 'string' && !NO_SHIFT.has(k) && ISO_RE.test(v) ? new Date(Date.parse(v) + SHIFT).toISOString() : v);
const clone = (o) => JSON.parse(JSON.stringify(o));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let setIndex = null; // files present in a named fixture set (fixtures/<set>/index.json)
async function fixture(name) {
  if (cache.has(name)) return cache.get(name);
  const tryLoad = async (url) => {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) return null;
    return JSON.parse(await res.text(), reviver);
  };
  let data = null;
  if (FIXTURES !== 'default') {
    if (!setIndex) setIndex = tryLoad(new URL(`${FIXTURES}/index.json`, FIX_BASE)).then((d) => new Set((d && d.files) || []));
    if ((await setIndex).has(name)) data = await tryLoad(new URL(`${FIXTURES}/${name}`, FIX_BASE));
  }
  if (data === null) data = await tryLoad(new URL(name, FIX_BASE));
  if (data === null) throw new ApiError(404, `No fixture ${name}`);
  cache.set(name, data);
  return data;
}

function matchEvent(e, q) {
  if (q.action && e.action !== q.action) return false;
  if (q.route && e.route !== q.route) return false;
  if (q.principal && (!e.principal || e.principal.id !== q.principal)) return false;
  if (q.control && !(e.findings || []).some((f) => f.control === q.control)) return false;
  if (q.q) {
    const needle = q.q.toLowerCase();
    const hay = [e.trace_id, e.session_id, e.excerpt, e.message, e.model, e.tool && e.tool.name, ...(e.findings || []).map(findingId)].join(' ').toLowerCase();
    if (!hay.includes(needle)) return false;
  }
  return true;
}

async function fixtureRequest(method, path, query, body) {
  await sleep(60 + Math.random() * 120);
  const seg = path.replace(/^\/api\//, '').split('/').filter(Boolean).map(decodeURIComponent);
  const [a, b, c] = seg;
  if (method === 'GET') {
    switch (a) {
      case 'stats': return clone(await fixture(`stats_${['1h', '24h', '7d'].includes(query.window) ? query.window : '24h'}.json`));
      case 'events': {
        const all = [...streamed, ...(await fixture('events.json')).events];
        if (b) {
          const evs = all.filter((e) => e.trace_id === b).sort((x, y) => x.seq - y.seq);
          if (evs.length) return { trace_id: b, chain_ok: true, events: clone(evs) };
          const d = await fixture('event_detail.json');
          if (d.trace_id === b) return clone(d);
          throw new ApiError(404, `Trace ${b} not found in the audit log.`);
        }
        let list = all.filter((e) => matchEvent(e, query));
        if (query.before_seq) list = list.filter((e) => e.seq < Number(query.before_seq));
        const limit = Math.min(Number(query.limit) || 100, 100000);
        const page = list.slice(0, limit);
        return { events: clone(page), next_before_seq: list.length > limit ? page[page.length - 1].seq : null };
      }
      case 'policy': return clone(await fixture(b === 'versions' ? 'policy_versions.json' : 'policy.json'));
      case 'controls': case 'coverage': case 'budgets': case 'perf': case 'signatures': case 'scenarios':
        return clone(await fixture(`${a}.json`));
      case 'approvals': return clone(await fixture('approvals.json'));
      default: throw new ApiError(404, `No fixture for GET ${path}`);
    }
  }
  if (method === 'POST') {
    if (a === 'approvals' && b) {
      const data = await fixture('approvals.json');
      const item = data.approvals.find((x) => x.id === b);
      if (!item) throw new ApiError(404, `Approval ${b} not found.`);
      if (item.status !== 'pending') throw new ApiError(409, `Approval ${b} is already ${item.status}.`);
      if (Date.parse(item.expires_at) < Date.now()) { item.status = 'expired'; throw new ApiError(409, `Approval ${b} expired.`); }
      item.status = body.decision === 'approve' ? 'approved' : 'denied';
      item.decided_at = new Date().toISOString();
      item.decided_by = 'admin';
      item.note = body.note || null;
      return { approval: clone(item) };
    }
    if (a === 'playground') {
      let name = 'playground_allow.json';
      if (body && body.untrusted_tool_result && body.untrusted_tool_result.trim()) name = 'playground_indirect.json';
      else if (body && /ignore|zignoruj|system prompt|AKIA|im_start|pickle|developer mode|4111/i.test(`${body.prompt} ${body.system || ''}`)) name = 'playground_block.json';
      return clone(await fixture(name));
    }
    if (a === 'scenarios' && b && c === 'run') {
      await sleep(700);
      try { return clone(await fixture(`scenario_run_${b}.json`)); } catch (_) { return clone(await fixture('scenario_run.json')); }
    }
    if (a === 'selftest') { await sleep(1500); return clone(await fixture('selftest.json')); }
  }
  throw new ApiError(404, `No fixture for ${method} ${path}`);
}

function fixtureStream({ onEvent, onStatus }) {
  let stopped = false;
  let i = 0;
  let timer = null;
  onStatus('connecting');
  (async () => {
    let src;
    try { src = (await fixture('stream.json')).events; } catch (_) { src = []; }
    const base = await fixture('events.json');
    let seq = Math.max(0, ...base.events.map((e) => e.seq));
    let prev = base.events.length ? base.events[0].hash : '0'.repeat(64);
    if (stopped) return;
    onStatus('live');
    const tick = () => {
      if (stopped || !src.length) return;
      const e = clone(src[i % src.length]);
      i += 1;
      seq += 1;
      e.seq = seq;
      e.ts = new Date().toISOString();
      e.trace_id = 'tr_SIM' + seq.toString(36).toUpperCase().padStart(6, '0') + Math.random().toString(36).slice(2, 10).toUpperCase();
      e.prev_hash = prev;
      e.hash = Array.from(crypto.getRandomValues(new Uint8Array(32)), (x) => x.toString(16).padStart(2, '0')).join('');
      prev = e.hash;
      streamed.unshift(e);
      if (streamed.length > 500) streamed.pop();
      onEvent(clone(e));
      timer = setTimeout(tick, 2500 + Math.random() * 2500);
    };
    timer = setTimeout(tick, 1500);
  })();
  return () => { stopped = true; clearTimeout(timer); };
}
