// Decision trace: renders every audit event of one trace_id.
import {
  html, actionPill, sevPill, tagList, timeEl, fmtMs, fmtUsd, fmtInt, fmtNum, shortHash, principalLabel,
  excerptHtml, strongestAction, findingId, isNum,
} from './util.js';

const LAYERS = [
  ['t0', 'T0 deterministic'],
  ['t1', 'T1 classifier'],
  ['t2', 'T2 judge'],
  ['upstream', 'Upstream'],
  ['gateway_overhead', 'Gateway overhead'],
];

const JUDGE_REASONS = {
  t1_grey_zone: 'T1 score in the grey zone',
  non_english: 'text is not in English (T1 is English-only)',
  side_effect_tool: 'side-effect tool call',
  harm_signal: 'harmful-request signal',
  monitor_async: 'monitor mode (async)',
};

function layersBlock(lat) {
  if (!lat) return '';
  const vals = LAYERS.map(([k]) => lat[k]).filter(isNum);
  const max = Math.max(1, ...vals);
  const rows = LAYERS.map(([k, label]) => {
    const v = lat[k];
    const pct = isNum(v) && v > 0 ? Math.max(0.6, (v / max) * 100) : 0;
    const cls = k === 'gateway_overhead' ? 'bar-overhead' : k === 'upstream' ? 'bar-upstream' : 'bar-layer';
    return html`<div class="lrow ${k === 'gateway_overhead' ? 'lrow-sum' : ''}">
      <span class="lname">${label}</span>
      <span class="ltrack"><span class="lbar ${cls}" style="width:${pct.toFixed(2)}%"></span></span>
      <span class="lval num">${isNum(v) ? fmtMs(v) : '–'}</span>
    </div>`;
  });
  return html`<div class="block">
    <h4>Layers <span class="hint">linear scale, longest layer = full width; gateway overhead = time added by Bouncer${isNum(lat.total) ? html`, total ${fmtMs(lat.total)}` : ''}</span></h4>
    <div class="layers">${rows}</div>
  </div>`;
}

function findingsBlock(fs) {
  if (!fs || !fs.length) return html`<div class="block"><h4>Findings</h4><p class="muted">No findings. Every enabled control for this direction ran and matched nothing.</p></div>`;
  const rows = fs.map((f) => html`<tr>
    <td><div class="mono fid">${findingId(f)}</div><div class="hint">tier ${f.tier || '–'}</div></td>
    <td>${sevPill(f.severity)}</td>
    <td class="num">${isNum(f.score) ? f.score.toFixed(2) : '–'}</td>
    <td>${actionPill(f.action)}</td>
    <td class="wrap">${f.reason || html`<span class="muted">–</span>`}
      ${f.evidence ? html`<div class="evidence mono">${f.evidence}</div>` : ''}
      ${Array.isArray(f.span) ? html`<div class="hint">span ${f.span[0]}-${f.span[1]}</div>` : ''}</td>
    <td>${tagList(f)}</td>
    <td class="nowrap">${f.signature_id ? html`<a href="#/signatures?id=${encodeURIComponent(f.signature_id)}">${f.signature_id}</a>` : html`<span class="muted">–</span>`}</td>
  </tr>`);
  return html`<div class="block"><h4>Findings <span class="hint">${fs.length}</span></h4>
    <div class="table-wrap"><table class="tbl tbl-findings">
      <thead><tr><th>Finding</th><th>Severity</th><th class="num">Score</th><th>Action</th><th>Why (evidence masked)</th><th>OWASP / ATLAS</th><th>Signature</th></tr></thead>
      <tbody>${rows}</tbody></table></div></div>`;
}

function judgeBlock(j) {
  if (!j) return '';
  if (!j.invoked) {
    return html`<div class="block"><h4>T2 judge</h4><p class="muted">Not invoked. T2 runs only for T1 grey-zone scores, non-English text and side-effect tool calls.</p></div>`;
  }
  const answers = Object.entries(j.answers || {}).map(([q, opts]) => {
    const entries = Object.entries(opts || {}).sort((a, b) => b[1] - a[1]);
    return html`<div class="judge-q"><div class="judge-qname mono">${q}</div>
      ${entries.map(([opt, p]) => html`<div class="prob">
        <span class="prob-opt">${opt}</span>
        <span class="prob-track"><span class="prob-bar" style="width:${(Math.max(0, Math.min(1, p)) * 100).toFixed(1)}%"></span></span>
        <span class="prob-val num">${isNum(p) ? p.toFixed(2) : '–'}</span>
      </div>`)}
    </div>`;
  });
  return html`<div class="block"><h4>T2 judge</h4>
    <dl class="facts facts-inline">
      <div><dt>Reason</dt><dd>${JUDGE_REASONS[j.reason] || j.reason || '–'}</dd></div>
      <div><dt>Backend</dt><dd class="mono">${j.backend || '–'}</dd></div>
      <div><dt>Latency</dt><dd class="num">${fmtMs(j.latency_ms)}</dd></div>
      <div><dt>Cached</dt><dd>${j.cached ? 'yes' : 'no'}</dd></div>
    </dl>
    <div class="judge-answers">${answers.length ? answers : html`<p class="muted">No answers recorded.</p>`}</div>
    <p class="hint">Probabilities per answer option, returned in one pass. Thresholds are in the policy (prompt_injection.judge, harmful_content.judge, tool_governance.goal_alignment).</p>
  </div>`;
}

function toolBlock(t) {
  if (!t) return '';
  let args = t.arguments;
  if (typeof args !== 'string') args = JSON.stringify(args, null, 2);
  return html`<div class="block"><h4>Tool call <span class="hint">arguments masked</span></h4>
    <div class="mono strong">${t.name}</div><pre class="code">${args || ''}</pre></div>`;
}

function usageBlock(u) {
  if (!u) return '';
  return html`<div class="block"><h4>Usage and cost</h4><dl class="facts facts-inline">
    <div><dt>Prompt tokens</dt><dd class="num">${fmtInt(u.prompt_tokens)}</dd></div>
    <div><dt>Completion tokens</dt><dd class="num">${fmtInt(u.completion_tokens)}</dd></div>
    <div><dt>Cost</dt><dd class="num">${fmtUsd(u.cost_usd)}</dd></div>
    <div><dt>GPU seconds</dt><dd class="num">${fmtNum(u.gpu_seconds)}</dd></div>
    <div><dt>Team budget left today</dt><dd class="num">${u.budget_left_usd == null ? '–' : fmtUsd(u.budget_left_usd)}</dd></div>
  </dl></div>`;
}

function chainBlock(e) {
  return html`<div class="block"><h4>Audit hash chain</h4><dl class="facts">
    <div><dt>seq</dt><dd class="mono">${e.seq ?? '–'}</dd></div>
    <div><dt>prev_hash</dt><dd class="mono hash">${e.prev_hash || '–'}</dd></div>
    <div><dt>hash</dt><dd class="mono hash">${e.hash || '–'}</dd></div>
  </dl></div>`;
}

function eventSection(e, idx, total) {
  const pol = e.policy || {};
  const kind = e.type && e.type !== 'decision' ? e.type : null;
  return html`<section class="trace-ev">
    <header class="trace-ev-head">
      <span class="step">${total > 1 ? `${idx + 1}/${total}` : ''}</span>
      ${actionPill(e.action)}
      ${e.enforced === false ? html`<span class="pill pill-outline" title="Monitor mode: recorded, not enforced">monitor: not enforced</span>` : ''}
      <span class="strong">${kind || e.direction || '–'}</span>
      <span class="muted">${e.route || ''}${e.model ? ` · ${e.model}` : ''}</span>
      <span class="spacer"></span>
      <span class="muted mono">seq ${e.seq ?? '–'}</span>
      ${timeEl(e.ts, { ms: true, date: true })}
    </header>
    ${e.message ? html`<div class="notice ${e.action === 'block' ? 'notice-error' : e.action === 'require_approval' ? 'notice-approval' : 'notice-info'}">
      <div class="notice-label">${kind ? 'System event' : 'Message returned to the agent'}${isNum(e.status_code) ? ` (HTTP ${e.status_code})` : ''}</div>${e.message}
      ${e.approval_id ? html`<div><a href="#/approvals">Open approval ${e.approval_id}</a></div>` : ''}</div>` : ''}
    <dl class="facts facts-inline">
      <div><dt>Principal</dt><dd>${principalLabel(e.principal)}</dd></div>
      <div><dt>Team</dt><dd>${(e.principal && e.principal.team) || '–'}</dd></div>
      <div><dt>Session</dt><dd class="mono">${e.session_id || '–'}</dd></div>
      <div><dt>Upstream</dt><dd>${e.upstream || '–'}</dd></div>
      <div><dt>HTTP status</dt><dd class="num">${e.status_code ?? '–'}</dd></div>
      <div><dt>Policy</dt><dd><a class="mono" href="#/policy" title="${pol.version || ''}">${shortHash(pol.version)}</a> · ${pol.profile || '–'} · ${pol.mode || '–'}</dd></div>
    </dl>
    ${layersBlock(e.latency_ms)}
    ${findingsBlock(e.findings)}
    ${judgeBlock(e.judge)}
    ${toolBlock(e.tool)}
    ${usageBlock(e.usage)}
    <div class="block"><h4>Excerpt <span class="hint">after redaction, as stored in the audit log</span></h4><pre class="code excerpt">${excerptHtml(e.excerpt)}</pre></div>
    ${chainBlock(e)}
    <details class="raw"><summary>Raw audit event (JSON)</summary><pre class="code">${JSON.stringify(e, null, 2)}</pre></details>
  </section>`;
}

export function renderTrace(t, { compact = false } = {}) {
  if (!t || !t.events || !t.events.length) return html`<p class="muted">No audit events for this trace.</p>`;
  const evs = [...t.events].sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
  const final = strongestAction(evs.map((e) => e.action));
  const first = evs[0];
  const chain = t.chain_ok === true
    ? html`<span class="ok-text" title="prev_hash and hash recomputed by the gateway for these events">hash chain verified</span>`
    : t.chain_ok === false ? html`<span class="bad-text">hash chain broken: run make verify-audit</span>` : '';
  return html`<div class="trace ${compact ? 'trace-compact' : ''}">
    <div class="trace-head">
      <div class="trace-title">
        <span class="muted">Trace</span> <span class="mono strong trace-id">${t.trace_id || first.trace_id}</span>
        <button type="button" class="btn btn-small" data-copy="${t.trace_id || first.trace_id}">Copy</button>
      </div>
      <div class="trace-sum">Final action ${actionPill(final)} · ${evs.length} decision${evs.length > 1 ? 's' : ''} · ${principalLabel(first.principal)} · ${chain}</div>
    </div>
    ${evs.map((e, i) => eventSection(e, i, evs.length))}
  </div>`;
}

// Delegated handler for copy buttons inside traces.
export function bindCopy(root) {
  root.addEventListener('click', async (ev) => {
    const b = ev.target.closest('[data-copy]');
    if (!b) return;
    try { await navigator.clipboard.writeText(b.getAttribute('data-copy')); b.textContent = 'Copied'; } catch (_) { b.textContent = 'Copy failed'; }
    setTimeout(() => { b.textContent = 'Copy'; }, 1200);
  });
}

