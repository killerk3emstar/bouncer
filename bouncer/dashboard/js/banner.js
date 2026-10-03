// Red banner shown when the last policy reload failed and the previous version is still active.
import { html, shortHash, timeEl } from './util.js';

export function reloadErrorDetail(err) {
  err = err || {};
  const snip = (err.snippet || []).map((l) => html`<div class="sl ${l.line === err.line ? 'err' : ''}"><span class="ln">${l.line}</span><span>${l.text}</span></div>${
    l.line === err.line && err.column ? html`<div class="sl"><span class="ln"></span><span class="caret">${' '.repeat(Math.max(0, err.column - 1))}^ ${err.message || ''}</span></div>` : ''}`);
  return html`<span class="mono">${err.path ? err.path + ': ' : ''}</span>${err.message || 'invalid policy'}${err.value !== undefined && err.value !== null ? html` (value <span class="mono">${err.value}</span>)` : ''}${err.line ? html` at line ${err.line}${err.column ? `, column ${err.column}` : ''}` : ''}.
    ${snip.length ? html`<div class="snippet">${snip}</div>` : ''}`;
}

export function reloadFailureBanner(p) {
  const err = p.reload.error || {};
  return html`<div class="banner-fail" role="alert">
    <h2>Policy reload failed${err.line ? ` at line ${err.line}` : ''}. The previous version is still active.</h2>
    <div>${p.path || 'policy file'}: ${reloadErrorDetail(err)}</div>
    <div style="margin-top:6px">Rejected version <span class="mono">${shortHash(p.reload.attempted_version)}</span> at ${timeEl(p.reload.at)}.
      Active version <a class="mono" href="#/policy">${shortHash(p.version)}</a>, loaded ${timeEl(p.loaded_at)}. Fix the file and save it again; the gateway reloads it automatically.</div>
  </div>`;
}
