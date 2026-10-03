// Signatures: the historical attack feed, its signature status and per-signature hits.
import { api } from '../api.js';
import { html, actionPill, sevPill, timeEl, fmtInt, errorBox, emptyRow, extLink, tagList } from '../util.js';

function host(u) {
  try { return new URL(u).hostname.replace(/^www\./, ''); } catch (_) { return u; }
}

export default {
  title: 'Signatures',
  mount(el, ctx) {
    let alive = true;
    let data = null;
    let q = '';
    const focus = ctx.query.get('id');
    el.innerHTML = '<p class="loading">Loading signature feed...</p>';

    const render = () => {
      const d = data;
      const needle = q.toLowerCase();
      const sigs = (d.signatures || []).filter((s) => !needle || [s.id, s.title, ...(s.cve || []), s.severity, s.action].join(' ').toLowerCase().includes(needle));
      el.innerHTML = String(html`
        <div class="view-head"><h1>Signatures</h1><span class="sub">Historical attack patterns from an external, signed feed. Changes apply without restart.</span></div>
        ${d.verified === false ? html`<div class="notice notice-error"><strong>Feed signature not verified.</strong> ${d.last_error || 'The feed was rejected.'}</div>`
          : d.last_error ? html`<div class="notice notice-error"><strong>Feed update rejected${d.last_error_at ? html` at ${timeEl(d.last_error_at)}` : ''}:</strong> ${d.last_error}</div>` : ''}
        <div class="card" style="margin-bottom:12px"><dl class="facts facts-inline">
          <div><dt>Feed</dt><dd class="strong">${d.feed || '–'}</dd></div>
          <div><dt>Version</dt><dd class="num">${d.version ?? '–'}</dd></div>
          <div><dt>Updated</dt><dd>${timeEl(d.updated, { date: true })}</dd></div>
          <div><dt>Signature (ed25519)</dt><dd>${d.verified ? html`<span class="ok-text">verified</span>` : html`<span class="bad-text">not verified</span>`}</dd></div>
          <div><dt>Public key</dt><dd class="mono">${d.public_key_fingerprint || '–'}</dd></div>
          <div><dt>Source</dt><dd class="mono wrap">${/^https?:\/\//.test(d.source || '') ? extLink(d.source) : d.source || '–'}</dd></div>
          <div><dt>Loaded</dt><dd>${timeEl(d.loaded_at)}</dd></div>
          <div><dt>Last check</dt><dd>${timeEl(d.last_check)}</dd></div>
          <div><dt>Signatures</dt><dd class="num">${fmtInt((d.signatures || []).length)}</dd></div>
        </dl></div>
        <div class="toolbar"><label class="field" style="flex:0 1 360px"><span>Filter</span><input type="search" id="sig-q" value="${q}" placeholder="id, title, CVE, severity"></label></div>
        <div class="card" style="padding:0"><div class="table-wrap"><table class="tbl">
          <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Action</th><th>Match on</th><th>CVE</th><th>OWASP</th><th>References</th><th class="num">Hits 24h</th><th>Last hit</th></tr></thead>
          <tbody>${sigs.length ? sigs.map((s) => html`<tr id="sig-${s.id}" class="${focus === s.id ? 'selected' : ''}">
            <td class="mono nowrap">${s.id}</td>
            <td class="wrap" style="min-width:220px">${s.title}<div class="hint">added ${s.added || '–'}</div></td>
            <td>${sevPill(s.severity)}</td>
            <td>${actionPill(s.action)}</td>
            <td><span class="mono">${s.match_type || '–'}</span><div class="hint">${(s.targets || []).join(', ')}</div></td>
            <td class="nowrap">${(s.cve || []).length ? (s.cve || []).map((c) => html`<div>${extLink('https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(c), c)}</div>`) : html`<span class="muted">none</span>`}</td>
            <td>${tagList({ owasp_llm: s.owasp_llm, owasp_agentic: s.owasp_agentic })}</td>
            <td>${(s.refs || []).length ? (s.refs || []).map((r) => html`<div class="nowrap">${extLink(r, host(r))}</div>`) : html`<span class="muted">–</span>`}</td>
            <td class="num">${s.hits_24h ? html`<a href="#/events?q=${encodeURIComponent('signatures.' + s.id)}">${fmtInt(s.hits_24h)}</a>` : '0'}</td>
            <td>${timeEl(s.last_hit)}</td>
          </tr>`) : emptyRow(10, (d.signatures || []).length ? 'No signature matches the filter.' : 'The feed has no signatures.')}</tbody>
        </table></div></div>`);
      const input = el.querySelector('#sig-q');
      input.addEventListener('input', () => {
        q = input.value;
        const pos = input.selectionStart;
        render();
        const ni = el.querySelector('#sig-q');
        ni.focus();
        ni.setSelectionRange(pos, pos);
      });
    };

    api('/api/signatures').then((d) => {
      if (!alive) return;
      data = d;
      render();
      if (focus) {
        const row = el.querySelector('#sig-' + CSS.escape(focus));
        if (row) row.scrollIntoView({ block: 'center' });
      }
    }).catch((e) => { if (alive) el.innerHTML = String(errorBox(e, 'GET /api/signatures')); });
    return () => { alive = false; };
  },
};
