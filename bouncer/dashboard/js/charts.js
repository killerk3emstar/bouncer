// Inline SVG charts. Colors come from CSS classes so the theme switch needs no redraw.
import { esc, fmtCompact, fmtMs, fmtInt, parseTs, settings } from './util.js';

// ---------------------------------------------------------------- tooltip
let tipEl = null;
export function initTooltip() {
  tipEl = document.createElement('div');
  tipEl.className = 'tip';
  tipEl.setAttribute('role', 'tooltip');
  document.body.appendChild(tipEl);
  const show = (target, x, y) => {
    const text = target.getAttribute('data-tip');
    if (!text) return;
    const lines = text.split('\n');
    tipEl.innerHTML = `<strong>${esc(lines[0])}</strong>` + lines.slice(1).map((l) => `<div>${esc(l)}</div>`).join('');
    tipEl.style.display = 'block';
    const r = tipEl.getBoundingClientRect();
    let left = x + 14;
    let top = y + 14;
    if (left + r.width > window.innerWidth - 8) left = x - r.width - 14;
    if (top + r.height > window.innerHeight - 8) top = y - r.height - 14;
    tipEl.style.left = Math.max(8, left) + 'px';
    tipEl.style.top = Math.max(8, top) + 'px';
  };
  document.addEventListener('pointermove', (e) => {
    const t = e.target.closest && e.target.closest('[data-tip]');
    if (t) show(t, e.clientX, e.clientY);
    else tipEl.style.display = 'none';
  });
  document.addEventListener('focusin', (e) => {
    const t = e.target.closest && e.target.closest('[data-tip]');
    if (t) { const r = t.getBoundingClientRect(); show(t, r.right, r.top); }
  });
  document.addEventListener('focusout', () => { tipEl.style.display = 'none'; });
  window.addEventListener('scroll', () => { tipEl.style.display = 'none'; }, true);
}

// ---------------------------------------------------------------- responsive mount
// draw(width) returns an SVG/HTML string; it is redrawn when the container width changes.
export function mountChart(el, draw) {
  if (!el) return () => {};
  let last = -1;
  const render = () => {
    const w = Math.floor(el.clientWidth);
    if (w <= 0 || w === last) return;
    last = w;
    el.innerHTML = draw(w);
  };
  render();
  const ro = new ResizeObserver(() => requestAnimationFrame(render));
  ro.observe(el);
  return () => ro.disconnect();
}

export function niceTicks(max, count = 4, minStep = 0) {
  if (!(max > 0)) return [0, Math.max(1, minStep)];
  const raw = Math.max(max / count, minStep);
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / mag;
  const step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10) * mag;
  const ticks = [];
  for (let v = 0; v <= max + step * 0.999; v += step) ticks.push(+v.toFixed(10));
  if (ticks.length < 2) ticks.push(step);
  return ticks;
}

const pad2 = (n) => String(n).padStart(2, '0');
function timeLabel(iso, bucketSeconds) {
  const d = parseTs(iso);
  if (!d) return '';
  const utc = settings.tz === 'utc';
  const hh = pad2(utc ? d.getUTCHours() : d.getHours());
  const mm = pad2(utc ? d.getUTCMinutes() : d.getMinutes());
  if (bucketSeconds >= 21600) {
    const mon = d.toLocaleString('en-US', { month: 'short', timeZone: utc ? 'UTC' : undefined });
    return `${mon} ${utc ? d.getUTCDate() : d.getDate()} ${hh}:${mm}`;
  }
  return `${hh}:${mm}`;
}

// Rounded top (data end) and square base.
function barPath(x, y, w, h, r = 4) {
  if (h <= 0 || w <= 0) return '';
  const rr = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`;
}

// ---------------------------------------------------------------- stacked columns over time
export function stackedColumns({ buckets, keys, labels, width, height = 150, bucketSeconds = 3600, unit = 'requests', aria }) {
  const m = { l: 44, r: 8, t: 10, b: 24 };
  const w = Math.max(120, width - m.l - m.r);
  const h = height - m.t - m.b;
  const totals = buckets.map((b) => keys.reduce((s, k) => s + (b[k] || 0), 0));
  const ticks = niceTicks(Math.max(1, ...totals), 3, 1);
  const top = ticks[ticks.length - 1];
  const n = Math.max(1, buckets.length);
  const band = w / n;
  const bw = Math.min(24, Math.max(2, band - 2));
  let s = `<svg class="chart" width="${width}" height="${height}" role="img" aria-label="${esc(aria || 'column chart')}">`;
  for (const t of ticks) {
    const y = m.t + h - (t / top) * h;
    s += `<line class="grid" x1="${m.l}" x2="${m.l + w}" y1="${y}" y2="${y}"/>`;
    s += `<text class="tick" x="${m.l - 6}" y="${y}" dy="0.32em" text-anchor="end">${fmtCompact(t)}</text>`;
  }
  buckets.forEach((b, i) => {
    const x = m.l + i * band + (band - bw) / 2;
    let y = m.t + h;
    const segs = keys.map((k) => [k, b[k] || 0]).filter(([, v]) => v > 0);
    segs.forEach(([k, v], j) => {
      const hh = (v / top) * h;
      y -= hh;
      const gap = j < segs.length - 1 || segs.length > 1 ? 1 : 0;
      const drawH = Math.max(1, hh - (j > 0 ? 2 : 0));
      if (j === segs.length - 1) s += `<path class="fill-${k}" d="${barPath(x, y, bw, drawH, 3)}"/>`;
      else s += `<rect class="fill-${k}" x="${x}" y="${y + (gap ? 0 : 0)}" width="${bw}" height="${drawH}"/>`;
    });
    const tip = [`${timeLabel(b.ts, bucketSeconds)}  total ${fmtInt(totals[i])} ${unit}`]
      .concat(keys.map((k) => `${labels[k] || k}: ${fmtInt(b[k] || 0)}`)).join('\n');
    s += `<rect class="hit" x="${m.l + i * band}" y="${m.t}" width="${band}" height="${h}" data-tip="${esc(tip)}"/>`;
  });
  s += `<line class="axis" x1="${m.l}" x2="${m.l + w}" y1="${m.t + h}" y2="${m.t + h}"/>`;
  const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(w / 70))));
  buckets.forEach((b, i) => {
    if (i % every !== 0) return;
    s += `<text class="tick" x="${m.l + i * band + band / 2}" y="${height - 6}" text-anchor="middle">${esc(timeLabel(b.ts, bucketSeconds))}</text>`;
  });
  return s + '</svg>';
}

// ---------------------------------------------------------------- latency p50..p95 range on a log axis
export function logRange({ rows, width, unitNote = 'ms, log scale' }) {
  const labelW = Math.min(170, Math.max(110, width * 0.22));
  const valueW = 150;
  const m = { l: labelW, r: valueW, t: 6, b: 26 };
  const w = Math.max(80, width - m.l - m.r);
  const rowH = 26;
  const height = m.t + rows.length * rowH + m.b;
  const lo = -1; // 0.1 ms
  const hi = 4; // 10 s
  const xOf = (v) => m.l + ((Math.log10(Math.max(0.1, Math.min(10000, v))) - lo) / (hi - lo)) * w;
  let s = `<svg class="chart" width="${width}" height="${height}" role="img" aria-label="latency p50 to p95 per layer, ${unitNote}">`;
  const ticks = [[0.1, '0.1 ms'], [1, '1 ms'], [10, '10 ms'], [100, '100 ms'], [1000, '1 s'], [10000, '10 s']];
  for (const [v, l] of ticks) {
    const x = xOf(v);
    s += `<line class="grid" x1="${x}" x2="${x}" y1="${m.t}" y2="${height - m.b}"/>`;
    s += `<text class="tick" x="${x}" y="${height - 8}" text-anchor="middle">${l}</text>`;
  }
  rows.forEach((r, i) => {
    const cy = m.t + i * rowH + rowH / 2;
    s += `<text class="label" x="${m.l - 10}" y="${cy}" dy="0.32em" text-anchor="end">${esc(r.label)}</text>`;
    if (r.p50 == null) {
      s += `<text class="tick" x="${m.l + 4}" y="${cy}" dy="0.32em">no data</text>`;
      return;
    }
    const x1 = xOf(r.p50);
    const x2 = xOf(r.p95 ?? r.p50);
    s += `<line class="range" x1="${x1}" x2="${x2}" y1="${cy}" y2="${cy}"/>`;
    s += `<circle class="p95" cx="${x2}" cy="${cy}" r="4"/>`;
    s += `<circle class="p50" cx="${x1}" cy="${cy}" r="4.5"/>`;
    s += `<text class="value" x="${width - valueW + 10}" y="${cy}" dy="0.32em">${esc(fmtMs(r.p50))} / ${esc(fmtMs(r.p95))}</text>`;
    const tip = `${r.label}\np50 ${fmtMs(r.p50)}\np95 ${fmtMs(r.p95)}` + (r.n != null ? `\nsamples ${fmtInt(r.n)}` : '') + (r.note ? `\n${r.note}` : '');
    s += `<rect class="hit" x="0" y="${cy - rowH / 2}" width="${width}" height="${rowH}" data-tip="${esc(tip)}"/>`;
  });
  return s + '</svg>';
}

// ---------------------------------------------------------------- histogram with labelled (possibly unequal) bins
export function histogram({ bins, width, height = 140, label }) {
  const m = { l: 40, r: 6, t: 8, b: 30 };
  const w = Math.max(100, width - m.l - m.r);
  const h = height - m.t - m.b;
  const total = bins.reduce((s, b) => s + (b.count || 0), 0);
  const ticks = niceTicks(Math.max(1, ...bins.map((b) => b.count || 0)), 3, 1);
  const top = ticks[ticks.length - 1];
  const n = Math.max(1, bins.length);
  const band = w / n;
  const bw = Math.max(2, Math.min(28, band - 2));
  const edge = (v) => (v >= 1000 ? `${+(v / 1000).toFixed(2)}s` : `${v}`);
  let s = `<svg class="chart" width="${width}" height="${height}" role="img" aria-label="${esc(label || 'histogram')}">`;
  for (const t of ticks) {
    const y = m.t + h - (t / top) * h;
    s += `<line class="grid" x1="${m.l}" x2="${m.l + w}" y1="${y}" y2="${y}"/>`;
    s += `<text class="tick" x="${m.l - 6}" y="${y}" dy="0.32em" text-anchor="end">${fmtCompact(t)}</text>`;
  }
  bins.forEach((b, i) => {
    const x = m.l + i * band + (band - bw) / 2;
    const bh = ((b.count || 0) / top) * h;
    if (bh > 0) s += `<path class="fill-neutral" d="${barPath(x, m.t + h - bh, bw, Math.max(1, bh), 3)}"/>`;
    const range = b.hi_ms == null ? `>= ${fmtMs(b.lo_ms)}` : `${fmtMs(b.lo_ms)} - ${fmtMs(b.hi_ms)}`;
    const share = total ? ` (${((100 * (b.count || 0)) / total).toFixed(1)}%)` : '';
    s += `<rect class="hit" x="${m.l + i * band}" y="${m.t}" width="${band}" height="${h}" data-tip="${esc(`${range}\n${fmtInt(b.count || 0)} samples${share}`)}"/>`;
    const lab = b.hi_ms == null ? `>${edge(b.lo_ms)}` : `${edge(b.hi_ms)}`;
    if (band >= 22 || i % 2 === 0) s += `<text class="tick" x="${m.l + i * band + band / 2}" y="${m.t + h + 13}" text-anchor="middle">${esc(lab)}</text>`;
  });
  s += `<line class="axis" x1="${m.l}" x2="${m.l + w}" y1="${m.t + h}" y2="${m.t + h}"/>`;
  s += `<text class="tick" x="${m.l + w}" y="${height - 3}" text-anchor="end">upper bin edge, ms</text>`;
  return s + '</svg>';
}

// ---------------------------------------------------------------- single-series line with area wash
export function lineChart({ points, width, height = 140, yFmt = (v) => fmtCompact(v), unit = '', bucketSeconds = 3600, aria }) {
  const m = { l: 44, r: 10, t: 10, b: 24 };
  const w = Math.max(100, width - m.l - m.r);
  const h = height - m.t - m.b;
  const vals = points.map((p) => p.v || 0);
  const ticks = niceTicks(Math.max(1e-9, ...vals), 3);
  const top = ticks[ticks.length - 1] || 1;
  const n = points.length;
  const xOf = (i) => m.l + (n <= 1 ? w / 2 : (i / (n - 1)) * w);
  const yOf = (v) => m.t + h - (v / top) * h;
  let s = `<svg class="chart" width="${width}" height="${height}" role="img" aria-label="${esc(aria || 'line chart')}">`;
  for (const t of ticks) {
    const y = yOf(t);
    s += `<line class="grid" x1="${m.l}" x2="${m.l + w}" y1="${y}" y2="${y}"/>`;
    s += `<text class="tick" x="${m.l - 6}" y="${y}" dy="0.32em" text-anchor="end">${esc(yFmt(t))}</text>`;
  }
  if (n) {
    const line = points.map((p, i) => `${i ? 'L' : 'M'}${xOf(i).toFixed(1)},${yOf(p.v || 0).toFixed(1)}`).join('');
    s += `<path class="area" d="${line}L${xOf(n - 1)},${m.t + h}L${xOf(0)},${m.t + h}Z"/>`;
    s += `<path class="line" d="${line}"/>`;
    const last = points[n - 1];
    s += `<circle class="dot" cx="${xOf(n - 1)}" cy="${yOf(last.v || 0)}" r="4"/>`;
    const band = w / Math.max(1, n);
    points.forEach((p, i) => {
      s += `<rect class="hit" x="${xOf(i) - band / 2}" y="${m.t}" width="${band}" height="${h}" data-tip="${esc(`${timeLabel(p.ts, bucketSeconds)}\n${yFmt(p.v || 0)} ${unit}`)}"/>`;
    });
    const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(w / 70))));
    points.forEach((p, i) => {
      if (i % every === 0) s += `<text class="tick" x="${xOf(i)}" y="${height - 6}" text-anchor="middle">${esc(timeLabel(p.ts, bucketSeconds))}</text>`;
    });
  }
  s += `<line class="axis" x1="${m.l}" x2="${m.l + w}" y1="${m.t + h}" y2="${m.t + h}"/>`;
  return s + '</svg>';
}
