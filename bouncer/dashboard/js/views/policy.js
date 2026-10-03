// Policy: active version, reload status, version history and unified diff between any two versions.
import { api } from '../api.js';
import { reloadErrorDetail } from '../banner.js';
import { html, raw, esc, timeEl, shortHash, errorBox, emptyRow } from '../util.js';

const STATUS_CLS = { active: 'st-ok', superseded: 'st-neutral', rejected: 'st-bad' };

// Line diff (LCS on the changed middle) -> list of ops {t: 'eq'|'del'|'add', a, b, text}.
function lineDiff(aText, bText) {
  const A = aText.split('\n');
  const B = bText.split('\n');
  let pre = 0;
  while (pre < A.length && pre < B.length && A[pre] === B[pre]) pre++;
  let suf = 0;
  while (suf < A.length - pre && suf < B.length - pre && A[A.length - 1 - suf] === B[B.length - 1 - suf]) suf++;
  const a = A.slice(pre, A.length - suf);
  const b = B.slice(pre, B.length - suf);
  const ops = [];
  for (let i = 0; i < pre; i++) ops.push({ t: 'eq', a: i + 1, b: i + 1, text: A[i] });
  const n = a.length;
  const m = b.length;
  if (n * m > 4e6) {
    a.forEach((t, i) => ops.push({ t: 'del', a: pre + i + 1, text: t }));
    b.forEach((t, j) => ops.push({ t: 'add', b: pre + j + 1, text: t }));
  } else {
    const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    let i = 0;
    let j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && a[i] === b[j]) { ops.push({ t: 'eq', a: pre + i + 1, b: pre + j + 1, text: a[i] }); i++; j++; }
      else if (j >= m || (i < n && dp[i + 1][j] >= dp[i][j + 1])) { ops.push({ t: 'del', a: pre + i + 1, text: a[i] }); i++; }
      else { ops.push({ t: 'add', b: pre + j + 1, text: b[j] }); j++; }
    }
  }
  for (let k = 0; k < suf; k++) ops.push({ t: 'eq', a: A.length - suf + k + 1, b: B.length - suf + k + 1, text: A[A.length - suf + k] });
  return ops;
}

function hunks(ops, ctx = 3) {
  const changed = ops.map((o, i) => (o.t !== 'eq' ? i : -1)).filter((i) => i >= 0);
  if (!changed.length) return [];
  const ranges = [];
  for (const i of changed) {
    const s = Math.max(0, i - ctx);
    const e = Math.min(ops.length - 1, i + ctx);
    if (ranges.length && s <= ranges[ranges.length - 1][1] + 1) ranges[ranges.length - 1][1] = e;
    else ranges.push([s, e]);
  }
  return ranges.map(([s, e]) => ops.slice(s, e + 1));
}

function diffHtml(ops) {
  const hs = hunks(ops);
  if (!hs.length) return html`<p class="muted">No differences.</p>`;
  const rows = [];
  for (const h of hs) {
    const aLines = h.filter((o) => o.t !== 'add');
    const bLines = h.filter((o) => o.t !== 'del');
    const aStart = aLines.length ? aLines[0].a : 0;
    const bStart = bLines.length ? bLines[0].b : 0;
    rows.push(`<div class="dl hunk"><span class="ln"></span><span class="ln"></span><span class="tx">@@ -${aStart},${aLines.length} +${bStart},${bLines.length} @@</span></div>`);
    for (const o of h) {
      const cls = o.t === 'eq' ? 'ctx' : o.t;
      rows.push(`<div class="dl ${cls}"><span class="ln">${o.a || ''}</span><span class="ln">${o.b || ''}</span><span class="tx">${esc(o.text)}</span></div>`);
    }
  }
  return raw(rows.join(''));
}

// Fallback when sources are not provided: render the server's unified diff text.
function serverDiffHtml(text) {
  if (!text) return html`<p class="muted">No diff available for this pair.</p>`;
  return raw(text.split('\n').map((l) => {
    const cls = l.startsWith('+++') || l.startsWith('---') ? 'meta' : l.startsWith('@@') ? 'hunk' : l.startsWith('+') ? 'add' : l.startsWith('-') ? 'del' : 'ctx';
    const body = cls === 'add' || cls === 'del' || cls === 'ctx' ? l.slice(1) : l;
    return `<div class="dl ${cls}"><span class="ln"></span><span class="tx">${esc(body)}</span></div>`;
  }).join(''));
}

function sourceHtml(src, errLine) {
  if (!src) return html`<p class="muted">The gateway did not send the policy source.</p>`;
  return raw(src.split('\n').map((l, i) => `<div class="dl ${i + 1 === errLine ? 'del' : ''}"><span class="ln">${i + 1}</span><span class="tx">${esc(l)}</span></div>`).join(''));
}

export default {
  title: 'Policy',
  mount(el, ctx) {
    let alive = true;
    const st = { pol: null, versions: [], ai: 1, bi: 0 };
    el.innerHTML = '<p class="loading">Loading policy...</p>';

    const render = () => {
      const p = st.pol;
      const vs = st.versions;
      const A = vs[st.ai];
      const B = vs[st.bi];
      let diff = html`<p class="muted">Select two versions.</p>`;
      if (A && B) {
        if (A === B) diff = html`<p class="muted">Same version selected twice.</p>`;
        else if (A.source != null && B.source != null) diff = diffHtml(lineDiff(A.source, B.source));
        else if (B.previous_version === A.version && B.diff) diff = serverDiffHtml(B.diff);
        else diff = html`<p class="muted">The gateway did not send sources for these versions; only the diff against the previous version is available.</p>`;
      }
      const failed = p && p.reload && p.reload.status === 'failed';
      el.innerHTML = String(html`
        <div class="view-head"><h1>Policy</h1><span class="sub">${p ? p.path : ''} · edit the file or use the editor below; the gateway reloads it within about a second</span></div>
        ${p ? html`<div class="card" style="margin-bottom:12px"><dl class="facts">
          <div><dt>Active version</dt><dd class="mono">${p.version} <button type="button" class="btn btn-small" data-copy="${p.version}">Copy</button></dd></div>
          <div><dt>Profile</dt><dd>${p.profile}</dd></div>
          <div><dt>Mode</dt><dd class="${p.mode === 'monitor' ? 'warn-text' : ''}">${p.mode}${p.mode === 'monitor' ? ': findings are recorded, nothing is blocked' : ''}</dd></div>
          <div><dt>Fail mode</dt><dd>${p.fail_mode || '–'}${p.fail_mode === 'closed' ? ' (a check that errors or times out blocks the request)' : p.fail_mode === 'open' ? ' (a check that errors or times out lets the request through and logs it)' : ''}</dd></div>
          <div><dt>Block response</dt><dd>${p.block_response || '–'}</dd></div>
          <div><dt>Loaded at</dt><dd>${timeEl(p.loaded_at, { date: true })}</dd></div>
          <div><dt>Last reload</dt><dd>${failed ? html`<span class="bad-text">failed</span>` : html`<span class="ok-text">ok</span>`} ${p.reload ? timeEl(p.reload.at, { date: true }) : ''}</dd></div>
          ${failed ? html`<div><dt>Reload error</dt><dd>${reloadErrorDetail(p.reload.error)}</dd></div>` : ''}
        </dl></div>` : ''}
        ${st.err ? errorBox(st.err, 'GET /api/policy/versions') : ''}
        <h2 style="margin:4px 0 8px">Version history <span class="hint">pick A and B to compare any two versions</span></h2>
        <div class="card" style="padding:0;margin-bottom:12px"><div class="table-wrap"><table class="tbl">
            <thead><tr><th title="Compare from">A</th><th title="Compare to">B</th><th>Loaded</th><th>Version</th><th>Status</th><th>Change</th></tr></thead>
            <tbody>${vs.length ? vs.map((v, i) => html`<tr class="${v.status === 'rejected' ? 'row-disabled' : ''}">
              <td><input type="radio" name="va" value="${i}" ${i === st.ai ? 'checked' : ''} aria-label="compare from ${shortHash(v.version)}"></td>
              <td><input type="radio" name="vb" value="${i}" ${i === st.bi ? 'checked' : ''} aria-label="compare to ${shortHash(v.version)}"></td>
              <td class="nowrap">${timeEl(v.loaded_at)}</td>
              <td><span class="mono" title="${v.version}">${shortHash(v.version)}</span></td>
              <td><span class="pill ${STATUS_CLS[v.status] || 'st-neutral'}">${v.status}</span></td>
              <td>${v.summary || ''}</td>
            </tr>`) : emptyRow(6, 'No version history.')}</tbody></table></div></div>
          <div class="card" style="margin-bottom:12px">
            <div class="card-head"><h2>Diff</h2>${A && B ? html`<span class="hint"><span class="mono">${shortHash(A.version)}</span> (A) to <span class="mono">${shortHash(B.version)}</span> (B)</span>` : ''}</div>
            ${B && B.status === 'rejected' && B.error ? html`<div class="notice notice-error">Version B was rejected: ${reloadErrorDetail(B.error)}</div>` : ''}
            <div class="diff">${diff}</div>
          </div>
        <details class="card"><summary class="strong" style="cursor:pointer">Active policy source${p ? html` <span class="mono hint">${shortHash(p.version)}</span>` : ''}</summary>
          <div class="diff" style="margin-top:8px;max-height:none">${sourceHtml(p && p.source)}</div></details>
        <details class="card" style="margin-top:12px" ${st.editOpen ? 'open' : ''} data-editor><summary class="strong" style="cursor:pointer">Edit policy <span class="hint">validated before it is written; an invalid file is never applied</span></summary>
          <textarea class="mono" data-policy-src spellcheck="false" style="width:100%;min-height:420px;margin-top:8px;font-size:12px;line-height:1.45">${st.draft != null ? st.draft : (p && p.source) || ''}</textarea>
          <div style="display:flex;gap:8px;align-items:center;margin-top:8px">
            <button type="button" class="btn" data-act="validate">Validate</button>
            <button type="button" class="btn btn-primary" data-act="save">Save and apply</button>
            <button type="button" class="btn" data-act="reset">Discard changes</button>
            <span data-edit-msg class="hint">${st.editMsg || ''}</span>
          </div>
          ${st.editErr ? html`<div class="notice notice-error" style="margin-top:8px">${reloadErrorDetail(st.editErr)}</div>` : ''}
        </details>`);
    };

    el.addEventListener('change', (e) => {
      if (e.target.name === 'va') st.ai = Number(e.target.value);
      if (e.target.name === 'vb') st.bi = Number(e.target.value);
      render();
    });
    el.addEventListener('input', (e) => {
      if (e.target.matches('[data-policy-src]')) st.draft = e.target.value;
    });
    el.addEventListener('toggle', (e) => {
      if (e.target.matches('[data-editor]')) st.editOpen = e.target.open;
    }, true);
    el.addEventListener('click', async (e) => {
      const act = e.target.closest('[data-act]');
      if (act) {
        const ta = el.querySelector('[data-policy-src]');
        const source = ta ? ta.value : '';
        st.draft = source;
        st.editOpen = true;
        if (act.dataset.act === 'reset') { st.draft = null; st.editErr = null; st.editMsg = ''; render(); return; }
        try {
          if (act.dataset.act === 'validate') {
            const r = await api('/api/policy/validate', { method: 'POST', body: { source } });
            st.editErr = r.ok ? null : r.error;
            st.editMsg = r.ok ? `Valid. Would become ${shortHash(r.version)} (profile ${r.profile}, mode ${r.mode}).` : 'Not valid; nothing was written.';
          } else {
            const r = await api('/api/policy', { method: 'PUT', body: { source, expected_version: st.pol && st.pol.version } });
            st.editErr = r.error || null;
            st.editMsg = r.changed ? `Saved and applied: now ${shortHash(r.version)}.` : (r.ok ? 'No change.' : 'Not applied.');
            if (r.changed) {
              st.draft = null;
              const [pol, vers] = await Promise.all([api('/api/policy'), api('/api/policy/versions')]);
              st.pol = pol;
              st.versions = vers.versions || [];
              st.bi = 0;
              st.ai = Math.min(1, st.versions.length - 1);
            }
          }
        } catch (err) {
          const body = err && err.body;
          st.editErr = body && body.error && body.error.line !== undefined ? body.error : null;
          st.editMsg = st.editErr ? 'Not valid; nothing was written.' : (err.message || 'Request failed');
        }
        render();
        return;
      }
      const b = e.target.closest('[data-copy]');
      if (!b) return;
      try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Copied'; } catch (_) { b.textContent = 'Copy failed'; }
    });

    (async () => {
      const [pol, vers] = await Promise.all([
        api('/api/policy').catch((e) => { st.polErr = e; return null; }),
        api('/api/policy/versions').catch((e) => { st.err = e; return { versions: [] }; }),
      ]);
      if (!alive) return;
      if (!pol && st.polErr) { el.innerHTML = String(errorBox(st.polErr, 'GET /api/policy')); return; }
      st.pol = pol;
      st.versions = vers.versions || [];
      // default: B = newest entry, A = its previous version (or the next entry)
      st.bi = 0;
      const prev = st.versions[0] && st.versions[0].previous_version;
      const pi = st.versions.findIndex((v, i) => i > 0 && v.version === prev);
      st.ai = pi >= 0 ? pi : Math.min(1, st.versions.length - 1);
      render();
    })();
    const off = ctx.app.onPolicy((p) => { if (st.pol && p && p.version !== st.pol.version) { st.pol = p; render(); } });
    return () => { alive = false; off(); };
  },
};
