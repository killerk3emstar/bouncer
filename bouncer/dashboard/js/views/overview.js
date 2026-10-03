// Overview: management view.
import { api } from '../api.js';
import { stackedColumns, logRange, mountChart } from '../charts.js';
import {
  html, fmtInt, fmtPct, fmtUsd, timeEl, shortHash, errorBox, ACTION_LABEL, RISKS, store, isNum,
} from '../util.js';

const WINDOWS = ['1h', '24h', '7d'];
const INTERVENTIONS = ['log', 'redact', 'require_approval', 'block'];
const LAYER_ROWS = [
  ['t0', 'T0 deterministic'], ['t1', 'T1 classifier'], ['t2', 'T2 judge'], ['gateway_overhead', 'Gateway overhead'], ['upstream', 'Upstream model'],
];

function kpis(t) {
  const req = t.requests || 0;
  const tile = (label, key, value, cls) => html`<div class="kpi">
    <div class="kpi-label">${cls ? html`<span class="swatch fill-bar-${cls}"></span>` : ''}${label}</div>
    <div class="kpi-value">${fmtInt(value)}</div>
    <div class="kpi-sub">${key ? (req ? fmtPct(value / req) + ' of requests' : 'no requests') : 'in window'}</div>
  </div>`;
  return html`<div class="kpis">
    ${tile('Requests', null, req, null)}
    ${tile('Allowed', 'allow', t.allow, 'allow')}
    ${tile('Logged', 'log', t.log, 'log')}
    ${tile('Redacted', 'redact', t.redact, 'redact')}
    ${tile('Held for approval', 'require_approval', t.require_approval, 'require_approval')}
    ${tile('Blocked', 'block', t.block, 'block')}
  </div>`;
}

function policyStrip(p) {
  if (!p) return '';
  const failed = p.reload && p.reload.status === 'failed';
  return html`<div class="card" style="margin-bottom:12px">
    <dl class="facts facts-inline">
      <div><dt>Active policy</dt><dd><a class="mono" href="#/policy" title="${p.version}">${shortHash(p.version)}</a></dd></div>
      <div><dt>Profile</dt><dd>${p.profile}</dd></div>
      <div><dt>Mode</dt><dd class="${p.mode === 'monitor' ? 'warn-text' : ''}">${p.mode}${p.mode === 'monitor' ? ' (nothing is blocked)' : ''}</dd></div>
      <div><dt>Fail mode</dt><dd>${p.fail_mode || '–'}</dd></div>
      <div><dt>Loaded</dt><dd>${timeEl(p.loaded_at)}</dd></div>
      <div><dt>Last reload</dt><dd>${failed ? html`<span class="bad-text">failed</span> ${timeEl(p.reload.at)}` : html`<span class="ok-text">ok</span> ${p.reload ? timeEl(p.reload.at) : ''}`}</dd></div>
      <div><dt>Signature feed</dt><dd>${p.feed ? html`${p.feed.name} v${p.feed.version} · ${p.feed.verified ? html`<span class="ok-text">signature verified</span>` : html`<span class="bad-text">not verified</span>`}` : '–'}</dd></div>
      <div><dt>T2 judge</dt><dd>${p.judge ? html`${p.judge.backend} · ${p.judge.healthy ? html`<span class="ok-text">healthy</span>` : html`<span class="bad-text">unreachable</span>`}` : '–'}</dd></div>
    </dl>
  </div>`;
}

function fwRow(label, s) {
  if (!s || !s.total) return '';
  const pct = (n) => (100 * n) / s.total;
  return html`<div style="margin-top:10px">
    <div class="row-flex" style="justify-content:space-between"><span class="strong">${label}</span>
      <span class="muted num">${s.covered} covered · ${s.partial} partial · ${s.not_covered} not covered</span></div>
    <div class="segbar" style="margin-top:4px" role="img" aria-label="${label}: ${s.covered} covered, ${s.partial} partial, ${s.not_covered} not covered of ${s.total}">
      ${s.covered ? html`<span class="seg-covered" style="width:${pct(s.covered)}%"></span>` : ''}
      ${s.partial ? html`<span class="seg-partial" style="width:${pct(s.partial)}%"></span>` : ''}
      ${s.not_covered ? html`<span class="seg-none" style="width:${pct(s.not_covered)}%"></span>` : ''}
    </div></div>`;
}

function posture(cov) {
  if (!cov || !cov.posture) return html`<div class="card"><h2>Security posture</h2><p class="muted">Coverage data unavailable.</p></div>`;
  const p = cov.posture;
  const c = p.controls || {};
  const t = p.tests || {};
  const gaps = (cov.risks || []).filter((r) => r.status !== 'covered').sort((a, b) => (a.status === 'none' ? -1 : 1) - (b.status === 'none' ? -1 : 1));
  return html`<div class="card">
    <div class="card-head"><h2>Security posture</h2><a href="#/coverage" class="hint">coverage matrix</a></div>
    <div class="row-flex" style="align-items:flex-end;gap:16px">
      <div class="hero" title="${p.formula || ''}">${p.score}<small> / 100</small></div>
      <div class="muted" style="font-size:12px;max-width:260px">${p.formula ? html`Score = ${p.formula}.` : ''} A risk counts as covered when a mapped control is enabled, in enforce mode, and its tests pass.</div>
    </div>
    ${fwRow('OWASP LLM Top 10 (2025)', p.by_framework && p.by_framework.owasp_llm_2025)}
    ${fwRow('OWASP Agentic Top 10 (2026)', p.by_framework && p.by_framework.owasp_agentic_2026)}
    <div class="legend" style="margin-top:8px"><span><span class="swatch seg-covered"></span>covered</span><span><span class="swatch seg-partial"></span>partial</span><span><span class="swatch seg-none"></span>not covered</span></div>
    <dl class="facts" style="margin-top:12px">
      <div><dt>Controls</dt><dd>${c.enabled ?? '–'} of ${c.total ?? '–'} enabled · ${c.enforce ?? '–'} enforce · ${c.monitor ?? '–'} monitor${c.disabled ? html` · <a class="bad-text" href="#/controls">${c.disabled} disabled</a>` : ''}</dd></div>
      <div><dt>Self-tests</dt><dd>${t.total ? html`${fmtInt(t.passed)} of ${fmtInt(t.total)} passing${t.failed ? html` · <span class="bad-text">${t.failed} failing</span>` : ''} · run ${timeEl(t.last_run)}` : 'not run yet'}</dd></div>
    </dl>
    ${gaps.length ? html`<div style="margin-top:10px"><div class="hint" style="margin-bottom:4px">Gaps</div>
      ${gaps.slice(0, 6).map((r) => html`<div class="wrap" style="font-size:12px;margin-bottom:3px">
        <span class="pill ${r.status === 'none' ? 'st-bad' : 'st-warn'}">${r.status === 'none' ? 'not covered' : 'partial'}</span>
        <span class="mono">${r.id}</span> ${r.name}${r.note ? html`<span class="muted">: ${r.note}</span>` : ''}</div>`)}
      ${gaps.length > 6 ? html`<a href="#/coverage" class="hint">${gaps.length - 6} more</a>` : ''}</div>` : ''}
  </div>`;
}

function threatsByControl(rows) {
  if (!rows || !rows.length) return html`<p class="empty-state">No findings in this window.</p>`;
  const max = Math.max(1, ...rows.map((r) => r.count || 0));
  return html`<div class="legend" style="margin-bottom:8px">${['block', 'require_approval', 'redact', 'log'].map((k) => html`<span><span class="swatch fill-bar-${k}"></span>${ACTION_LABEL[k]}</span>`)}</div>
  <div class="hbars">${rows.map((r) => {
    const tip = `${r.control}\n${['block', 'require_approval', 'redact', 'log'].map((k) => `${ACTION_LABEL[k]}: ${fmtInt(r[k] || 0)}`).join('\n')}`;
    return html`<a class="hbar" href="#/events?control=${encodeURIComponent(r.control)}" data-tip="${tip}" style="color:inherit;text-decoration:none">
      <span class="hbar-label mono">${r.control}</span>
      <span class="hbar-track"><span class="hbar-fill" style="width:${(100 * (r.count || 0)) / max}%">
        ${['block', 'require_approval', 'redact', 'log'].filter((k) => r[k] > 0).map((k) => html`<span class="fill-bar-${k}" style="flex:${r[k]} 1 0"></span>`)}
      </span></span>
      <span class="hbar-value">${fmtInt(r.count)}</span></a>`;
  })}</div>
  <p class="hint" style="margin-top:8px">Requests with at least one finding from the control, split by the finding's action. Click a row to see the events.</p>`;
}

function threatsByOwasp(rows) {
  if (!rows || !rows.length) return html`<p class="empty-state">No findings in this window.</p>`;
  const max = Math.max(1, ...rows.map((r) => r.count || 0));
  return html`<div class="hbars hbars-wide">${rows.map((r) => html`<div class="hbar" data-tip="${r.id} ${r.name || RISKS[r.id] || ''}\n${fmtInt(r.count)} findings">
      <span class="hbar-label"><span class="mono strong">${r.id}</span> ${r.name || RISKS[r.id] || ''}</span>
      <span class="hbar-track"><span class="hbar-fill fill-bar-neutral" style="width:${(100 * (r.count || 0)) / max}%"></span></span>
      <span class="hbar-value">${fmtInt(r.count)}</span></div>`)}</div>
  <p class="hint" style="margin-top:8px">Findings per OWASP LLM 2025 / Agentic 2026 risk. A finding can map to several risks.</p>`;
}

function spend(b) {
  if (!b || !b.teams || !b.teams.length) return html`<p class="empty-state">No budgets configured.</p>`;
  const maxRatio = Math.max(1.15, ...b.teams.map((t) => (t.usd_per_day ? t.spent_usd / t.usd_per_day : 0) * 1.05));
  const stateCls = { ok: 'st-ok', downgraded: 'st-warn', blocked: 'st-bad' };
  return html`<div class="hbars" style="gap:12px;margin-top:16px">${b.teams.map((t) => {
    const ratio = t.usd_per_day ? t.spent_usd / t.usd_per_day : 0;
    const cls = ratio >= 1 ? 'block' : ratio >= 0.8 ? 'redact' : 'neutral';
    const refPos = (100 / maxRatio);
    const tip = `${t.team}\nspent ${fmtUsd(t.spent_usd)} of ${fmtUsd(t.usd_per_day)} per day (${fmtPct(ratio, 0)})\nrequests today ${fmtInt(t.requests)}\ntokens last minute ${fmtInt(t.tokens_last_minute)} of ${fmtInt(t.tokens_per_minute)}\nGPU seconds last hour ${isNum(t.gpu_seconds_last_hour) ? t.gpu_seconds_last_hour : '–'} of ${fmtInt(t.gpu_seconds_per_hour)}`;
    return html`<div class="hbar" data-tip="${tip}">
      <span class="hbar-label"><span class="strong">${t.team}</span> <span class="pill ${stateCls[t.state] || 'st-neutral'}">${t.state}</span></span>
      <span class="hbar-track"><span class="hbar-fill fill-bar-${cls}" style="width:${Math.min(100, (100 * ratio) / maxRatio)}%"></span>
        <span class="hbar-ref" style="left:${refPos}%"></span></span>
      <span class="hbar-value">${fmtUsd(t.spent_usd)} / ${fmtUsd(t.usd_per_day)}</span></div>`;
  })}</div>
  <div class="hint" style="margin-top:10px">Bar = spend today as a share of the team's daily budget; black line = 100% of budget. Over budget: ${b.on_exceed ? `${b.on_exceed.action} to ${b.on_exceed.downgrade_to || '–'}, then ${b.on_exceed.hard_limit_action}` : '–'}. Resets ${b.resets_at ? new Date(b.resets_at).toISOString().slice(11, 16) + ' UTC' : '–'}.</div>`;
}

function render(el, st) {
  const { win, stats, budgets, coverage, policy, errors } = st;
  const t = stats ? stats.totals : null;
  el.innerHTML = String(html`
    <div class="view-head">
      <h1>Overview</h1>
      <div class="seg" role="group" aria-label="Time window">${WINDOWS.map((w) => html`<button type="button" data-win="${w}" aria-pressed="${String(w === win)}">${w}</button>`)}</div>
      <span class="sub">${stats ? html`${timeEl(stats.from, { date: true })} to ${timeEl(stats.to, { date: true })}` : ''}</span>
      <span class="spacer"></span>
      <span class="hint">refreshes every 20 s${stats ? html` · generated ${timeEl(stats.generated_at)}` : ''}</span>
    </div>
    ${errors.map((e) => errorBox(e.err, e.what))}
    ${policyStrip(policy)}
    ${t ? kpis(t) : ''}
    <div class="grid g-1-2">
      ${posture(coverage)}
      <div class="card">
        <div class="card-head"><h2>Traffic</h2><span class="hint">${stats && stats.usage ? html`spend in window ${fmtUsd(stats.usage.cost_usd)} · ${fmtInt((stats.usage.prompt_tokens || 0) + (stats.usage.completion_tokens || 0))} tokens` : ''}</span></div>
        <div class="hint">All requests per ${stats ? bucketLabel(stats.series.bucket_seconds) : 'bucket'}</div>
        <div id="ch-total"></div>
        <div class="row-flex" style="margin-top:10px;justify-content:space-between">
          <span class="hint">Interventions per ${stats ? bucketLabel(stats.series.bucket_seconds) : 'bucket'} (everything that was not a plain allow)</span>
          <span class="legend">${INTERVENTIONS.map((k) => html`<span><span class="swatch fill-bar-${k}"></span>${ACTION_LABEL[k]}</span>`)}</span>
        </div>
        <div id="ch-int"></div>
      </div>
    </div>
    <div class="grid g2">
      <div class="card"><div class="card-head"><h2>Top threat categories by control</h2></div>${stats ? threatsByControl(stats.top_controls) : ''}</div>
      <div class="card"><div class="card-head"><h2>Top threat categories by OWASP risk</h2></div>${stats ? threatsByOwasp(stats.top_owasp) : ''}</div>
    </div>
    <div class="grid g2">
      <div class="card"><div class="card-head"><h2>Spend vs daily budget per team</h2><span class="hint">USD, today${budgets ? ` (${budgets.date})` : ''}</span></div>${spend(budgets)}</div>
      <div class="card"><div class="card-head"><h2>Latency added per layer</h2><span class="hint">p50 (filled dot) to p95 (ring), log scale</span></div>
        <div id="ch-lat"></div>
        ${stats && stats.t2 ? html`<dl class="facts facts-inline" style="margin-top:10px">
          <div><dt>T2 escalation rate</dt><dd class="strong">${fmtPct(stats.t2.escalation_rate)} <span class="muted">(${fmtInt(stats.t2.escalations)} of ${fmtInt(t.requests)} requests)</span></dd></div>
          <div><dt>Judge cache hit rate</dt><dd>${fmtPct(stats.t2.cache_hit_rate, 0)}</dd></div>
          <div><dt>Judge timeouts</dt><dd>${fmtInt(stats.t2.timeouts)}</dd></div>
        </dl>` : ''}
        <p class="hint" style="margin-top:6px">T2 runs only on escalation, so its latency applies to the escalated share of requests. Upstream model time shown for comparison. Details in <a href="#/performance">Performance</a>.</p>
      </div>
    </div>`);
  if (stats && !(t && t.requests)) {
    const msg = '<p class="empty-state">No requests in this window. Send a request through the gateway or use the Playground.</p>';
    el.querySelector('#ch-total').innerHTML = msg;
    el.querySelector('#ch-int').innerHTML = '';
  }
  if (stats) {
    const s = stats.series;
    const totals = s.buckets.map((b) => ({ ts: b.ts, total: ['allow', ...INTERVENTIONS].reduce((a, k) => a + (b[k] || 0), 0) }));
    if (t && t.requests) st.cleanups.push(mountChart(el.querySelector('#ch-total'), (w) => stackedColumns({ buckets: totals, keys: ['total'], labels: { total: 'requests' }, width: w, height: 90, bucketSeconds: s.bucket_seconds, aria: 'requests per bucket' })));
    if (t && t.requests) st.cleanups.push(mountChart(el.querySelector('#ch-int'), (w) => stackedColumns({ buckets: s.buckets, keys: INTERVENTIONS, labels: ACTION_LABEL, width: w, height: 140, bucketSeconds: s.bucket_seconds, aria: 'interventions per bucket by action' })));
    const rows = LAYER_ROWS.map(([k, label]) => ({ label, ...(stats.latency_ms[k] || {}), note: k === 't2' ? 'escalated requests only' : null }));
    st.cleanups.push(mountChart(el.querySelector('#ch-lat'), (w) => logRange({ rows, width: w })));
  }
}

function bucketLabel(sec) {
  if (sec === 300) return '5 minutes';
  if (sec === 3600) return 'hour';
  if (sec === 21600) return '6 hours';
  if (sec === 86400) return 'day';
  return `${sec} s`;
}

export default {
  title: 'Overview',
  mount(el, ctx) {
    const st = { win: store.get('window', '24h'), cleanups: [], errors: [] };
    if (!WINDOWS.includes(st.win)) st.win = '24h';
    let alive = true;
    const load = async () => {
      el.querySelector('.view-head') || (el.innerHTML = '<p class="loading">Loading overview...</p>');
      const settle = (p, what) => p.then((v) => v, (err) => { st.errors.push({ err, what }); return null; });
      st.errors = [];
      const [stats, budgets, coverage] = await Promise.all([
        settle(api('/api/stats', { query: { window: st.win } }), 'GET /api/stats'),
        settle(api('/api/budgets'), 'GET /api/budgets'),
        settle(api('/api/coverage'), 'GET /api/coverage'),
      ]);
      if (!alive) return;
      Object.assign(st, { stats, budgets, coverage, policy: ctx.app.policy });
      st.cleanups.forEach((f) => f());
      st.cleanups = [];
      render(el, st);
    };
    el.addEventListener('click', (e) => {
      const b = e.target.closest('[data-win]');
      if (!b) return;
      st.win = b.dataset.win;
      store.set('window', st.win);
      load();
    });
    const off = ctx.app.onPolicy((p) => { st.policy = p; if (st.stats !== undefined) { st.cleanups.forEach((f) => f()); st.cleanups = []; render(el, st); } });
    load();
    const timer = setInterval(load, 20000);
    return () => { alive = false; clearInterval(timer); off(); st.cleanups.forEach((f) => f()); };
  },
};
