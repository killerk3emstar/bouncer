// Performance: per-layer latency, escalation to T2, cache hit rates, throughput.
import { api } from '../api.js';
import { histogram, lineChart, mountChart } from '../charts.js';
import { html, fmtMs, fmtInt, fmtPct, errorBox, emptyRow, timeEl, store, isNum } from '../util.js';

const WINDOWS = ['1h', '24h', '7d'];
const REASONS = { t1_grey_zone: 'T1 grey zone', non_english: 'non-English text', side_effect_tool: 'side-effect tool call', harm_signal: 'harmful-request signal', monitor_async: 'monitor mode (async)' };

function tile(label, value, sub) {
  return html`<div class="kpi"><div class="kpi-label">${label}</div><div class="kpi-value">${value}</div><div class="kpi-sub">${sub || ''}</div></div>`;
}

// rates span 0.001 to 1000 req/s: keep two significant digits for small values
const fmtRate = (v) => (v >= 10 ? v.toFixed(0) : v >= 1 ? v.toFixed(1) : v >= 0.1 ? v.toFixed(2) : v.toFixed(3));
const bucketLabel = (s) => (!s ? 'bucket' : s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`);

export default {
  title: 'Performance',
  mount(el) {
    let alive = true;
    let cleanups = [];
    let win = store.get('window', '24h');
    if (!WINDOWS.includes(win)) win = '24h';

    const render = (p, err) => {
      cleanups.forEach((f) => f());
      cleanups = [];
      const layers = (p && p.layers) || [];
      const t2 = (p && p.t2) || {};
      const t1 = (p && p.t1) || {};
      const thr = (p && p.throughput_rps) || {};
      const reasons = Object.entries(t2.by_reason || {});
      const maxReason = Math.max(1, ...reasons.map(([, v]) => v));
      el.innerHTML = String(html`
        <div class="view-head"><h1>Performance</h1>
          <div class="seg" role="group" aria-label="Time window">${WINDOWS.map((w) => html`<button type="button" data-win="${w}" aria-pressed="${String(w === win)}">${w}</button>`)}</div>
          <span class="sub">${p ? html`${fmtInt(p.requests)} requests · generated ${timeEl(p.generated_at)}` : ''}</span></div>
        ${err ? errorBox(err, 'GET /api/perf') : ''}
        ${p ? html`
        <div class="kpis">
          ${tile('Throughput, last 60 s', isNum(thr.current) ? fmtRate(thr.current) + ' req/s' : '–', `peak ${isNum(thr.peak) ? fmtRate(thr.peak) : '–'} req/s (${bucketLabel(thr.bucket_seconds)} avg)`)}
          ${tile('T2 escalation rate', fmtPct(t2.escalation_rate), `${fmtInt(t2.escalations)} of ${fmtInt(p.requests)} requests`)}
          ${tile('T2 judge cache hit rate', fmtPct(t2.cache_hit_rate, 0), `${fmtInt(t2.cache_hits)} hits · backend ${t2.backend || '–'}`)}
          ${tile('T2 timeouts', fmtInt(t2.timeouts), `fail mode ${t2.fail_mode || '–'}`)}
          ${tile('T1 cache hit rate', fmtPct(t1.cache_hit_rate, 0), `${fmtInt(t1.fragments_scanned)} fragments scanned`)}
          ${tile('Gateway overhead p95', fmtMs((layers.find((l) => l.layer === 'gateway_overhead') || {}).p95), 'time added by Bouncer')}
        </div>
        <div class="card" style="padding:0;margin-bottom:12px"><div class="table-wrap"><table class="tbl">
          <thead><tr><th>Layer</th><th class="num">Samples</th><th class="num">p50</th><th class="num">p95</th><th class="num">p99</th><th class="num">max</th><th>Runs when</th></tr></thead>
          <tbody>${layers.length ? layers.map((l) => html`<tr><td class="strong">${l.label || l.layer}</td><td class="num">${fmtInt(l.n)}</td>
            <td class="num">${fmtMs(l.p50)}</td><td class="num">${fmtMs(l.p95)}</td><td class="num">${fmtMs(l.p99)}</td><td class="num">${fmtMs(l.max)}</td>
            <td class="hint">${{ t0: 'every request', t1: 'new untrusted fragments (user text, tool results, tool descriptions)', t2: 'escalations only', upstream: 'requests forwarded to the model', gateway_overhead: 'every request; includes T2 when escalated' }[l.layer] || ''}</td></tr>`) : emptyRow(7, 'No latency samples yet.')}</tbody>
        </table></div></div>
        <div class="grid g3">${layers.map((l, i) => html`<div class="card"><div class="card-head"><h2>${l.label || l.layer}</h2><span class="hint">p50 ${fmtMs(l.p50)} · p95 ${fmtMs(l.p95)}</span></div><div id="h-${i}"></div></div>`)}
          <div class="card"><div class="card-head"><h2>Why requests escalate to T2</h2></div>
            ${reasons.length ? html`<div class="hbars hbars-wide">${reasons.map(([k, v]) => html`<div class="hbar"><span class="hbar-label">${REASONS[k] || k}</span>
              <span class="hbar-track"><span class="hbar-fill fill-bar-neutral" style="width:${(100 * v) / maxReason}%"></span></span><span class="hbar-value">${fmtInt(v)}</span></div>`)}</div>`
              : html`<p class="empty-state">No escalations in this window.</p>`}
          </div>
        </div>
        <div class="card"><div class="card-head"><h2>Throughput</h2><span class="hint">requests per second, averaged per bucket</span></div><div id="thr"></div></div>` : ''}`);
      if (!p) return;
      layers.forEach((l, i) => {
        cleanups.push(mountChart(el.querySelector('#h-' + i), (w) => histogram({ bins: l.histogram || [], width: w, height: 140, label: `${l.label} latency histogram` })));
      });
      const pts = (thr.series || []).map((s) => ({ ts: s.ts, v: s.rps }));
      cleanups.push(mountChart(el.querySelector('#thr'), (w) => lineChart({ points: pts, width: w, height: 150, yFmt: fmtRate, unit: 'req/s', bucketSeconds: thr.bucket_seconds || 3600, aria: 'throughput in requests per second' })));
    };

    let last = null;
    const load = async () => {
      try {
        last = await api('/api/perf', { query: { window: win } });
        if (alive) render(last);
      } catch (e) {
        if (alive) render(last, e);
      }
    };
    el.addEventListener('click', (e) => {
      const b = e.target.closest('[data-win]');
      if (!b) return;
      win = b.dataset.win;
      store.set('window', win);
      load();
    });
    el.innerHTML = '<p class="loading">Loading performance data...</p>';
    load();
    const timer = setInterval(load, 20000);
    return () => { alive = false; clearInterval(timer); cleanups.forEach((f) => f()); };
  },
};
