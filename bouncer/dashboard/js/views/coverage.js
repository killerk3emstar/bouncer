// Coverage: OWASP LLM Top 10 2025 and OWASP Agentic Top 10 2026 x controls.
import { api } from '../api.js';
import { html, errorBox, fmtInt, safeUrl, timeEl } from '../util.js';

const STATUS = {
  covered: ['covered', 'st-ok'],
  partial: ['partial', 'st-warn'],
  none: ['not covered', 'st-bad'],
};

function cell(risk, control, c, enabled) {
  if (!c) return html`<td><div class="cell cell-empty" aria-label="not mapped"></div></td>`;
  const st = !enabled ? 'none' : c.status;
  const label = st === 'covered' ? 'covered' : st === 'partial' ? 'partial' : enabled ? 'not covered' : 'control disabled';
  const tip = `${risk.id} x ${control}\n${label}\n${fmtInt(c.tests || 0)} test case${c.tests === 1 ? '' : 's'}`;
  return html`<td><div class="cell cell-${st}" data-tip="${tip}" tabindex="0" aria-label="${tip.replace(/\n/g, ', ')}">${st === 'none' ? (enabled ? '0' : 'off') : fmtInt(c.tests || 0)}</div></td>`;
}

export default {
  title: 'Coverage',
  mount(el) {
    el.innerHTML = '<p class="loading">Loading coverage...</p>';
    let alive = true;
    (async () => {
      let cov;
      let ctl = null;
      try {
        [cov, ctl] = await Promise.all([api('/api/coverage'), api('/api/controls').catch(() => null)]);
      } catch (e) { if (alive) el.innerHTML = String(errorBox(e, 'GET /api/coverage')); return; }
      if (!alive) return;
      const enabled = {};
      ((ctl && ctl.controls) || []).forEach((c) => { enabled[c.id] = c.enabled; });
      const controls = cov.controls || [];
      const p = cov.posture || {};
      const fwName = Object.fromEntries((cov.frameworks || []).map((f) => [f.id, f]));
      const groups = (cov.frameworks || []).map((f) => ({ fw: f, risks: (cov.risks || []).filter((r) => r.framework === f.id) }));
      const ncols = controls.length + 2;
      el.innerHTML = String(html`
        <div class="view-head">
          <h1>Coverage</h1>
          <span class="sub">${p.total ? html`${p.covered} of ${p.total} risks covered, ${p.partial} partial, <span class="${p.not_covered ? 'bad-text' : ''}">${p.not_covered} not covered</span> · posture score ${p.score} / 100` : ''}</span>
        </div>
        <div class="card" style="margin-bottom:12px">
          <div class="legend">
            <span><span class="legend-cell cell-covered"></span>covered: control enabled, enforce mode, tests pass (number = test cases)</span>
            <span><span class="legend-cell cell-partial"></span>partial: mitigates part of the risk, monitor mode, or failing tests</span>
            <span><span class="legend-cell cell-none"></span>mapped control disabled</span>
            <span><span class="legend-cell cell-empty"></span>not mapped</span>
          </div>
          ${p.tests ? html`<div class="hint" style="margin-top:6px">Test counts from the last self-test run ${timeEl(p.tests.last_run)}: ${fmtInt(p.tests.passed)} of ${fmtInt(p.tests.total)} passing.</div>` : ''}
        </div>
        <div class="card"><div class="table-wrap">
          <table class="matrix">
            <thead><tr><th style="text-align:left">Risk</th><th style="text-align:left">Status</th>
              ${controls.map((c) => html`<th class="vert ${enabled[c] === false ? 'off' : ''}" title="${c}${enabled[c] === false ? ' (disabled)' : ''}"><span>${c}</span></th>`)}</tr></thead>
            <tbody>${groups.map((g) => html`
              <tr class="fw"><th colspan="${ncols}">${safeUrl(g.fw.url) ? html`<a href="${safeUrl(g.fw.url)}" target="_blank" rel="noopener noreferrer">${g.fw.name}</a>` : g.fw.name}</th></tr>
              ${g.risks.map((r) => {
                const [label, cls] = STATUS[r.status] || [r.status, 'st-neutral'];
                return html`<tr>
                  <td class="risk"><span class="rid">${r.id}</span>${safeUrl(r.url) ? html`<a href="${safeUrl(r.url)}" target="_blank" rel="noopener noreferrer">${r.name}</a>` : r.name || ''}
                    ${r.note ? html`<div class="note">${r.note}</div>` : ''}</td>
                  <td class="rstat"><span class="pill ${cls}">${label}</span><div class="hint">${fmtInt(r.tests || 0)} tests</div></td>
                  ${controls.map((c) => cell(r, c, (r.cells || {})[c], enabled[c] !== false))}
                </tr>`;
              })}`)}
            </tbody>
          </table>
        </div></div>
        <p class="hint" style="margin-top:8px">Risk names as published by the OWASP GenAI Security Project (${Object.values(fwName).map((f) => f.name).join('; ')}). Gaps are listed in the risk notes; they are out of scope or planned, not hidden.</p>`);
    })();
    return () => { alive = false; };
  },
};
