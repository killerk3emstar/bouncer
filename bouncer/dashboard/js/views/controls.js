// Controls: every control in the policy, its state, OWASP mapping, tests and triggers.
import { api } from '../api.js';
import { html, actionPill, timeEl, fmtInt, fmtNum, errorBox, emptyRow, tagList, shortHash } from '../util.js';

function stateCell(c) {
  if (!c.enabled) return html`<span class="pill st-bad">disabled</span>`;
  return html`<span class="pill st-ok">enabled</span>`;
}

function modeCell(c) {
  if (!c.enabled) return '';
  if (c.mode === 'monitor') return html`<span class="pill st-warn" title="Findings are recorded, nothing is blocked">monitor</span>`;
  return html`<span class="pill st-neutral">${c.mode || '–'}</span>`;
}

function testsCell(t) {
  if (!t || !t.total) return html`<span class="bad-text" title="No test cases tagged with this control">no tests</span>`;
  const status = t.failed ? html`<span class="bad-text">${t.failed} failing</span>` : html`<span class="ok-text">all pass</span>`;
  return html`<div class="nowrap">${status}</div>
    <div class="hint nowrap" title="allow cases / block or redact cases">${t.allow} allow · ${t.block} block</div>`;
}

function settingsCell(s) {
  const entries = Object.entries(s || {});
  if (!entries.length) return html`<span class="muted">–</span>`;
  return html`<div>${entries.map(([k, v]) => html`<span class="kv" title="${k}: ${fmtNum(v)}">${k} <b>${fmtNum(v)}</b></span>`)}</div>`;
}

export default {
  title: 'Controls',
  mount(el) {
    el.innerHTML = '<p class="loading">Loading controls...</p>';
    let alive = true;
    (async () => {
      let d;
      try { d = await api('/api/controls'); } catch (e) { if (alive) el.innerHTML = String(errorBox(e, 'GET /api/controls')); return; }
      if (!alive) return;
      const cs = d.controls || [];
      const enabled = cs.filter((c) => c.enabled);
      const disabled = cs.filter((c) => !c.enabled);
      const monitor = enabled.filter((c) => c.mode === 'monitor');
      const tests = cs.reduce((a, c) => ({ total: a.total + (c.tests ? c.tests.total : 0), failed: a.failed + (c.tests ? c.tests.failed : 0) }), { total: 0, failed: 0 });
      const ordered = [...disabled, ...enabled];
      el.innerHTML = String(html`
        <div class="view-head">
          <h1>Controls</h1>
          <span class="sub">${cs.length} controls · ${enabled.length} enabled · ${enabled.length - monitor.length} enforce · ${monitor.length} monitor ·
            ${disabled.length ? html`<span class="bad-text">${disabled.length} disabled</span>` : '0 disabled'} ·
            tests ${fmtInt(tests.total - tests.failed)} of ${fmtInt(tests.total)} passing</span>
          <span class="spacer"></span>
          <span class="hint">policy <a class="mono" href="#/policy">${shortHash(d.policy_version)}</a></span>
        </div>
        ${disabled.length ? html`<div class="notice notice-error"><strong>${disabled.length} control${disabled.length > 1 ? 's are' : ' is'} disabled:</strong>
          ${disabled.map((c) => c.id).join(', ')}. No checks run for ${disabled.length > 1 ? 'them' : 'it'}, and the posture score drops. A control is disabled when its section is missing from policy/bouncer.yaml.</div>` : ''}
        ${monitor.length ? html`<div class="notice notice-warn"><strong>Monitor mode:</strong> ${monitor.map((c) => c.id).join(', ')} record findings but never block.</div>` : ''}
        <div class="card" style="padding:0"><div class="table-wrap"><table class="tbl">
          <thead><tr><th>Control</th><th>State</th><th>Action</th><th>Settings and thresholds</th><th>OWASP / ATLAS</th><th>Tests</th><th>Triggered</th></tr></thead>
          <tbody>${ordered.length ? ordered.map((c) => html`<tr class="${c.enabled ? '' : 'row-disabled'}" id="ctl-${c.id}">
            <td style="min-width:190px;max-width:260px"><div class="mono strong">${c.id}</div><div>${c.title || ''}</div>
              <div class="hint wrap">${c.enabled ? c.description || '' : c.disabled_reason || 'Section missing from the policy.'}</div>
              <div class="hint">tiers ${(c.tiers || []).join(', ') || '–'}</div></td>
            <td class="nowrap">${stateCell(c)}<div style="margin-top:3px">${modeCell(c)}</div></td>
            <td class="nowrap">${!c.enabled ? html`<span class="muted">–</span>` : c.action === 'downgrade' ? html`<span class="pill st-warn">downgrade</span>` : actionPill(c.action)}</td>
            <td style="max-width:300px">${settingsCell(c.settings)}${c.directions && c.directions.length ? html`<div class="hint">directions: ${c.directions.join(', ')}</div>` : ''}</td>
            <td style="max-width:150px">${tagList(c)}</td>
            <td>${testsCell(c.tests)}</td>
            <td style="min-width:110px"><a class="nowrap" href="#/events?control=${encodeURIComponent(c.id)}" title="Open events with findings from ${c.id}">${fmtInt(c.triggers ? c.triggers.count_24h : 0)} in 24h</a>
              <div class="hint">last ${timeEl(c.triggers && c.triggers.last_triggered)}</div></td>
          </tr>`) : emptyRow(7, 'No controls reported by the gateway.')}</tbody>
        </table></div></div>
        <p class="hint" style="margin-top:8px">Tests are the YAML cases in tests/cases/ tagged with the control; "block" counts block, redact and approval expectations. Run them with make test or the self-test button in Playground.</p>`);
    })();
    return () => { alive = false; };
  },
};
