// Approvals: pending require_approval requests with approve / deny.
import { api } from '../api.js';
import { html, timeEl, parseTs, principalLabel, errorBox, emptyRow, tagList, fmtDuration } from '../util.js';

function args(a) {
  if (a === null || a === undefined) return '';
  return typeof a === 'string' ? a : JSON.stringify(a, null, 2);
}

function expiresCell(a) {
  const d = parseTs(a.expires_at);
  if (!d) return html`<span class="muted">–</span>`;
  const s = (d.getTime() - Date.now()) / 1000;
  if (s <= 0) return html`<span class="bad-text">expired</span>`;
  return html`<span class="${s < 120 ? 'warn-text' : ''} num" data-expires="${a.expires_at}">in ${fmtDuration(s)}</span>`;
}

const STATUS_CLS = { approved: 'st-ok', denied: 'st-bad', expired: 'st-neutral', pending: 'st-approval' };

export default {
  title: 'Approvals',
  mount(el, ctx) {
    let alive = true;
    const armed = new Map();
    el.innerHTML = '<p class="loading">Loading approvals...</p>';

    const render = (d, err) => {
      const all = (d && d.approvals) || [];
      const pending = all.filter((a) => a.status === 'pending').sort((x, y) => String(x.expires_at).localeCompare(String(y.expires_at)));
      const done = all.filter((a) => a.status !== 'pending').sort((x, y) => String(y.decided_at || y.expires_at).localeCompare(String(x.decided_at || x.expires_at)));
      el.innerHTML = String(html`
        <div class="view-head"><h1>Approvals</h1><span class="sub">${pending.length} pending</span><span class="spacer"></span><span class="hint">refreshes every 5 s</span></div>
        ${err ? errorBox(err, 'GET /api/approvals') : ''}
        <div class="notice notice-info">An approval allows exactly the held call (same tool, same arguments hash) for the policy's approval TTL. The agent has to send the call again; any other call is checked as usual. Arguments are shown masked.</div>
        <div class="card" style="padding:0;margin-bottom:12px"><div class="table-wrap"><table class="tbl">
          <thead><tr><th>Requested</th><th title="Sorted by expiry, soonest first">Expires</th><th>Principal</th><th>Tool call</th><th>Why it was held</th><th>Decision</th></tr></thead>
          <tbody>${pending.length ? pending.map((a) => html`<tr data-id="${a.id}">
            <td class="nowrap">${timeEl(a.created_at)}<div class="hint mono">${a.id}</div></td>
            <td class="nowrap">${expiresCell(a)}</td>
            <td class="nowrap">${principalLabel(a.principal)}<div class="hint">${a.principal ? a.principal.team : ''}</div></td>
            <td style="min-width:240px;max-width:380px"><div class="mono strong">${a.tool}</div><pre class="code" style="max-height:160px">${args(a.arguments)}</pre>
              <div class="hint mono" title="${a.arguments_hash || ''}">args ${a.arguments_hash ? a.arguments_hash.slice(0, 19) : '–'}</div></td>
            <td style="min-width:240px"><div class="mono">${a.finding || ''}</div><div class="wrap">${a.reason || ''}</div>
              <div style="margin-top:4px">${tagList(a)}</div>
              ${a.trace_id ? html`<div><a href="#/events/${encodeURIComponent(a.trace_id)}">Open decision trace</a></div>` : ''}</td>
            <td style="min-width:220px">
              <input type="text" class="note" placeholder="Note (optional, stored in the audit log)" style="width:100%;margin-bottom:6px" value="${armed.get(a.id + ':note') || ''}">
              <div class="row-flex">
                <button type="button" class="btn btn-approve ${armed.get(a.id) === 'approve' ? 'armed' : ''}" data-decide="approve">${armed.get(a.id) === 'approve' ? 'Confirm approve' : 'Approve'}</button>
                <button type="button" class="btn btn-deny ${armed.get(a.id) === 'deny' ? 'armed' : ''}" data-decide="deny">${armed.get(a.id) === 'deny' ? 'Confirm deny' : 'Deny'}</button>
              </div>
              <div class="hint row-msg"></div>
            </td>
          </tr>`) : emptyRow(6, 'No pending approvals. Requests held by a require_approval rule appear here.')}</tbody>
        </table></div></div>
        <h2 style="margin:16px 0 8px">Recent decisions</h2>
        <div class="card" style="padding:0"><div class="table-wrap"><table class="tbl">
          <thead><tr><th>Requested</th><th>Status</th><th>Decided</th><th>Principal</th><th>Tool</th><th>Reason</th><th>Note</th></tr></thead>
          <tbody>${done.length ? done.map((a) => html`<tr>
            <td class="nowrap">${timeEl(a.created_at)}<div class="hint mono">${a.id}</div></td>
            <td><span class="pill ${STATUS_CLS[a.status] || 'st-neutral'}">${a.status}</span></td>
            <td class="nowrap">${a.decided_at ? html`${timeEl(a.decided_at)}<div class="hint">by ${a.decided_by || '–'}</div>` : html`<span class="muted">${a.status === 'expired' ? 'no decision before expiry' : '–'}</span>`}</td>
            <td>${principalLabel(a.principal)}</td>
            <td class="mono">${a.tool}</td>
            <td class="wrap">${a.reason || ''}${a.trace_id ? html` <a href="#/events/${encodeURIComponent(a.trace_id)}">trace</a>` : ''}</td>
            <td class="wrap">${a.note || html`<span class="muted">–</span>`}</td>
          </tr>`) : emptyRow(7, 'No decisions yet.')}</tbody>
        </table></div></div>`);
    };

    let last = null;
    const load = async () => {
      if (el.querySelector('input.note:focus')) return; // do not wipe a note being typed
      try {
        last = await api('/api/approvals');
        if (alive) render(last);
      } catch (e) {
        if (alive) render(last, e);
      }
    };

    el.addEventListener('input', (e) => {
      if (e.target.classList.contains('note')) armed.set(e.target.closest('tr').dataset.id + ':note', e.target.value);
    });
    el.addEventListener('click', async (e) => {
      const b = e.target.closest('[data-decide]');
      if (!b) return;
      const tr = b.closest('tr');
      const id = tr.dataset.id;
      const decision = b.dataset.decide;
      if (armed.get(id) !== decision) {
        armed.set(id, decision);
        render(last);
        setTimeout(() => { if (armed.get(id) === decision) { armed.delete(id); if (alive) render(last); } }, 5000);
        return;
      }
      armed.delete(id);
      const note = (tr.querySelector('input.note') || {}).value || '';
      b.disabled = true;
      try {
        await api(`/api/approvals/${encodeURIComponent(id)}`, { method: 'POST', body: { decision, note } });
        armed.delete(id + ':note');
        await load();
        ctx.app.refreshApprovals();
      } catch (err) {
        b.disabled = false;
        const msg = tr.querySelector('.row-msg');
        if (msg) msg.innerHTML = String(errorBox(err, `${decision} ${id}`));
      }
    });

    load();
    const timer = setInterval(load, 5000);
    const countdown = setInterval(() => {
      el.querySelectorAll('[data-expires]').forEach((n) => {
        const d = parseTs(n.dataset.expires);
        const s = d ? (d.getTime() - Date.now()) / 1000 : 0;
        n.textContent = s > 0 ? 'in ' + fmtDuration(s) : 'expired';
        n.classList.toggle('warn-text', s > 0 && s < 120);
        n.classList.toggle('bad-text', s <= 0);
      });
    }, 1000);
    return () => { alive = false; clearInterval(timer); clearInterval(countdown); };
  },
};

