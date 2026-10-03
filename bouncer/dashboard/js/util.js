// Shared helpers: safe HTML templating, formatting, small domain helpers.

export class Raw {
  constructor(s) { this.s = s; }
  toString() { return this.s; }
}
export const raw = (s) => new Raw(String(s));

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ESC[c]);

function renderVal(v) {
  if (v === null || v === undefined || v === false) return '';
  if (v instanceof Raw) return v.s;
  if (Array.isArray(v)) return v.map(renderVal).join('');
  return esc(String(v));
}

// Tagged template: every interpolation is escaped unless it is a Raw (from html`` or raw()).
export function html(strings, ...vals) {
  let out = strings[0];
  for (let i = 0; i < vals.length; i++) out += renderVal(vals[i]) + strings[i + 1];
  return new Raw(out);
}

// Only http(s) links and in-app hashes are rendered as links.
export function safeUrl(u) {
  if (typeof u !== 'string') return null;
  if (u.startsWith('#/')) return u;
  try {
    const p = new URL(u, location.href);
    if (p.protocol === 'http:' || p.protocol === 'https:') return p.href;
  } catch (_) { /* not a URL */ }
  return null;
}

export function extLink(url, label) {
  const u = safeUrl(url);
  if (!u) return html`<span>${label || url}</span>`;
  return html`<a href="${u}" target="_blank" rel="noopener noreferrer">${label || url}</a>`;
}

// ---------------------------------------------------------------- settings
export const store = {
  get(k, d = null) { try { const v = localStorage.getItem('bouncer.' + k); return v === null ? d : v; } catch (_) { return d; } },
  set(k, v) { try { if (v === null) localStorage.removeItem('bouncer.' + k); else localStorage.setItem('bouncer.' + k, v); } catch (_) { /* storage blocked */ } },
};

export const settings = {
  get tz() { return store.get('tz', 'local'); },
  set tz(v) { store.set('tz', v); },
};

// ---------------------------------------------------------------- formatting
const nf0 = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });
const nf1 = new Intl.NumberFormat('en-US', { minimumFractionDigits: 1, maximumFractionDigits: 1 });
const nf2 = new Intl.NumberFormat('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

export const isNum = (v) => typeof v === 'number' && Number.isFinite(v);

export function fmtInt(v) { return isNum(v) ? nf0.format(v) : '–'; }

export function fmtCompact(v) {
  if (!isNum(v)) return '–';
  if (Math.abs(v) >= 1e6) return nf1.format(v / 1e6) + 'M';
  if (Math.abs(v) >= 1e4) return nf1.format(v / 1e3) + 'K';
  return nf0.format(v);
}

export function fmtMs(v) {
  if (!isNum(v)) return '–';
  if (v === 0) return '0 ms';
  if (v < 1) return v.toFixed(2) + ' ms';
  if (v < 10) return v.toFixed(1) + ' ms';
  if (v < 1000) return nf0.format(v) + ' ms';
  return (v / 1000).toFixed(2) + ' s';
}

export function fmtUsd(v) {
  if (!isNum(v)) return '–';
  if (v === 0) return '$0.00';
  const a = Math.abs(v);
  if (a < 0.01) return (v < 0 ? '-$' : '$') + a.toFixed(4);
  if (a < 1) return (v < 0 ? '-$' : '$') + a.toFixed(4).replace(/0{1,2}$/, '');
  return (v < 0 ? '-$' : '$') + nf2.format(a);
}

export function fmtPct(r, digits = 1) {
  if (!isNum(r)) return '–';
  const p = r * 100;
  if (p > 0 && p < 0.1) return '<0.1%';
  return p.toFixed(digits) + '%';
}

export function fmtNum(v, digits = 2) {
  if (v === null || v === undefined) return '–';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (!isNum(v)) return String(v);
  return Number.isInteger(v) ? nf0.format(v) : String(+v.toFixed(digits));
}

const pad = (n, w = 2) => String(n).padStart(w, '0');

export function parseTs(iso) {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? new Date(t) : null;
}

// Short clock time, with date when not today. Title carries the full UTC ISO value.
export function fmtTime(iso, { ms = false, date = 'auto' } = {}) {
  const d = parseTs(iso);
  if (!d) return '–';
  const utc = settings.tz === 'utc';
  const Y = utc ? d.getUTCFullYear() : d.getFullYear();
  const M = (utc ? d.getUTCMonth() : d.getMonth()) + 1;
  const D = utc ? d.getUTCDate() : d.getDate();
  const h = utc ? d.getUTCHours() : d.getHours();
  const m = utc ? d.getUTCMinutes() : d.getMinutes();
  const s = utc ? d.getUTCSeconds() : d.getSeconds();
  const now = new Date();
  const sameDay = utc
    ? now.getUTCFullYear() === Y && now.getUTCMonth() + 1 === M && now.getUTCDate() === D
    : now.getFullYear() === Y && now.getMonth() + 1 === M && now.getDate() === D;
  let out = `${pad(h)}:${pad(m)}:${pad(s)}`;
  if (ms) out += '.' + pad(d.getUTCMilliseconds(), 3);
  if (date === true || (date === 'auto' && !sameDay)) out = `${Y}-${pad(M)}-${pad(D)} ${out}`;
  return out;
}

export function timeEl(iso, opts) {
  if (!iso) return html`<span class="muted">–</span>`;
  return html`<time datetime="${iso}" title="${iso}">${fmtTime(iso, opts)}</time>`;
}

export function fmtDuration(sec) {
  if (!isNum(sec)) return '–';
  const a = Math.abs(sec);
  if (a < 60) return Math.round(a) + ' s';
  if (a < 3600) return Math.floor(a / 60) + ' min ' + pad(Math.round(a % 60)) + ' s';
  if (a < 86400) return Math.floor(a / 3600) + ' h ' + pad(Math.floor((a % 3600) / 60)) + ' min';
  return Math.floor(a / 86400) + ' d ' + Math.floor((a % 86400) / 3600) + ' h';
}

export function fmtRel(iso) {
  const d = parseTs(iso);
  if (!d) return '–';
  const s = (d.getTime() - Date.now()) / 1000;
  return s >= 0 ? 'in ' + fmtDuration(s) : fmtDuration(-s) + ' ago';
}

export function shortHash(h, n = 12) {
  if (!h) return '–';
  const s = String(h);
  const i = s.indexOf(':');
  return i >= 0 ? s.slice(i + 1, i + 1 + n) : s.slice(0, n);
}

// ---------------------------------------------------------------- domain
export const ACTIONS = ['allow', 'log', 'redact', 'require_approval', 'block'];
export const ACTION_LABEL = { allow: 'allow', log: 'log', redact: 'redact', require_approval: 'approval', block: 'block' };
export const ACTION_RANK = { allow: 0, log: 1, redact: 2, require_approval: 3, block: 4 };
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function actionPill(a, extra = '') {
  if (!a) return html`<span class="muted">–</span>`;
  const cls = ACTION_RANK[a] !== undefined ? a : 'unknown';
  return html`<span class="pill act act-${cls} ${extra}">${ACTION_LABEL[a] || a}</span>`;
}

export function sevPill(s) {
  if (!s) return html`<span class="muted">–</span>`;
  return html`<span class="sev sev-${s}">${s}</span>`;
}

export function strongestAction(list) {
  let best = null;
  for (const a of list) if (a && (best === null || (ACTION_RANK[a] ?? -1) > (ACTION_RANK[best] ?? -1))) best = a;
  return best;
}

export function findingId(f) { return f ? `${f.control}.${f.rule}` : ''; }

export function topFinding(ev) {
  const fs = (ev && ev.findings) || [];
  if (!fs.length) return null;
  return [...fs].sort((a, b) =>
    (ACTION_RANK[b.action] ?? -1) - (ACTION_RANK[a.action] ?? -1) ||
    (SEV_RANK[b.severity] ?? -1) - (SEV_RANK[a.severity] ?? -1) ||
    (b.score ?? 0) - (a.score ?? 0))[0];
}

export const RISKS = {
  LLM01: 'Prompt Injection', LLM02: 'Sensitive Information Disclosure', LLM03: 'Supply Chain',
  LLM04: 'Data and Model Poisoning', LLM05: 'Improper Output Handling', LLM06: 'Excessive Agency',
  LLM07: 'System Prompt Leakage', LLM08: 'Vector and Embedding Weaknesses', LLM09: 'Misinformation',
  LLM10: 'Unbounded Consumption',
  ASI01: 'Agent Goal Hijack', ASI02: 'Tool Misuse and Exploitation', ASI03: 'Identity and Privilege Abuse',
  ASI04: 'Agentic Supply Chain Vulnerabilities', ASI05: 'Unexpected Code Execution', ASI06: 'Memory and Context Poisoning',
  ASI07: 'Insecure Inter-Agent Communication', ASI08: 'Cascading Failures', ASI09: 'Human-Agent Trust Exploitation',
  ASI10: 'Rogue Agents',
};
const LLM_SLUG = {
  LLM01: 'llm01-prompt-injection', LLM02: 'llm022025-sensitive-information-disclosure', LLM03: 'llm032025-supply-chain',
  LLM04: 'llm042025-data-and-model-poisoning', LLM05: 'llm052025-improper-output-handling', LLM06: 'llm062025-excessive-agency',
  LLM07: 'llm072025-system-prompt-leakage', LLM08: 'llm082025-vector-and-embedding-weaknesses', LLM09: 'llm092025-misinformation',
  LLM10: 'llm102025-unbounded-consumption',
};
const ATLAS = {
  'AML.T0051': 'LLM Prompt Injection', 'AML.T0051.000': 'LLM Prompt Injection: Direct', 'AML.T0051.001': 'LLM Prompt Injection: Indirect',
  'AML.T0054': 'LLM Jailbreak', 'AML.T0057': 'LLM Data Leakage', 'AML.T0010': 'AI Supply Chain Compromise', 'AML.T0053': 'AI Agent Tool Invocation',
};

export function riskUrl(id) {
  if (LLM_SLUG[id]) return `https://genai.owasp.org/llmrisk/${LLM_SLUG[id]}/`;
  if (/^ASI\d\d$/.test(id)) return 'https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/';
  return null;
}

export function tagList(f) {
  const out = [];
  for (const id of f.owasp_llm || []) out.push(html`<a class="tag tag-llm" href="${riskUrl(id) || '#'}" target="_blank" rel="noopener noreferrer" title="OWASP ${id}:2025 ${RISKS[id] || ''}">${id}</a>`);
  for (const id of f.owasp_agentic || []) out.push(html`<a class="tag tag-asi" href="${riskUrl(id) || '#'}" target="_blank" rel="noopener noreferrer" title="OWASP Agentic ${id} ${RISKS[id] || ''}">${id}</a>`);
  for (const id of f.atlas || []) out.push(html`<a class="tag tag-atlas" href="https://atlas.mitre.org/techniques/${id}" target="_blank" rel="noopener noreferrer" title="MITRE ATLAS ${id} ${ATLAS[id] || ''}">${id}</a>`);
  return out.length ? html`<span class="tags">${out}</span>` : html`<span class="muted">–</span>`;
}

export function principalLabel(p) {
  if (!p || !p.id) return html`<span class="muted" title="No principal matched the API key">unauthenticated</span>`;
  return html`<span title="team ${p.team || '–'}">${p.id}</span>`;
}

// Highlight [REDACTED:...] markers inside already-escaped text.
export function excerptHtml(text) {
  if (!text) return html`<span class="muted">(empty)</span>`;
  const e = esc(text).replace(/\[(REDACTED|REMOVED):[^\]\s]{1,80}\]/g, (m) => `<mark class="redacted">${m}</mark>`);
  return raw(e);
}

export function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

export function errorBox(err, what) {
  const msg = err && err.message ? err.message : String(err);
  const status = err && err.status ? ` (HTTP ${err.status})` : '';
  return html`<div class="notice notice-error" role="alert"><strong>${what || 'Request'} failed${status}.</strong> ${msg}</div>`;
}

export function emptyRow(cols, text) {
  return html`<tr class="empty"><td colspan="${cols}">${text}</td></tr>`;
}
