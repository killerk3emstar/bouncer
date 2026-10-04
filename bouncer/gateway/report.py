"""One-page printable management summary (GET /reports/summary)."""

from __future__ import annotations

import html
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

CSS = """
body{font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;color:#111;margin:32px auto;max-width:860px;padding:0 16px;background:#fff}
h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:24px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px}
.muted{color:#555}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}
.kpi{border:1px solid #ddd;padding:8px 10px}.kpi b{display:block;font-size:20px;font-variant-numeric:tabular-nums}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}td,th{border-bottom:1px solid #eee;padding:4px 6px;text-align:left}th.n{text-align:right}
th{font-weight:600;color:#333}td.n{text-align:right}.bad{color:#b00020}.warn{color:#8a5a00}
@media print{body{margin:0}}
"""


def _e(v: Any) -> str:
    return html.escape(str(v)) if v is not None else "-"


def _ms(v: Any) -> str:
    if v is None:
        return "-"
    return f"{v:.1f} ms" if v < 1000 else f"{v / 1000:.2f} s"


def _pct(part: float, whole: float) -> str:
    """Share with one decimal, rounded half up like the dashboard (Number.toFixed): 2 of 32 -> 6.3%."""
    if not whole:
        return "0%"
    return f"{Decimal(100 * part / whole).quantize(Decimal('0.1'), rounding=ROUND_HALF_UP)}%"


def _when(v: Any) -> str:
    """2026-10-04T01:13:43.567Z -> 2026-10-04 01:13 UTC."""
    if not isinstance(v, str) or len(v) < 16:
        return _e(v)
    return _e(f"{v[:10]} {v[11:16]} UTC")


STATUS_LABEL = {"none": "not covered"}


def render_summary(stats: dict[str, Any], coverage: dict[str, Any], budgets: dict[str, Any], policy: dict[str, Any]) -> str:
    t = stats["totals"]
    n = t["requests"] or 0
    pct = lambda k: _pct(t[k], n)  # noqa: E731
    allowed = t["allow"] + t["log"]
    allowed_pct = _pct(allowed, n)
    logged = f", {t['log']} with findings logged" if t["log"] else ""
    lat = stats.get("latency_ms", {})
    ov = lat.get("gateway_overhead", {})
    posture = coverage["posture"]
    rows_budget = "".join(
        f"<tr><td>{_e(b['team'])}</td><td class=n>${b['spent_usd']:.4f}</td><td class=n>{f"${b['usd_per_day']:.2f}" if b['usd_per_day'] is not None else '-'}</td>"
        f"<td class={'bad' if b['state'] in ('blocked', 'exceeded') else ('warn' if b['state'] in ('warning', 'downgraded') else '')}>{_e(b['state'])}</td></tr>"
        for b in budgets["teams"]
    )
    rows_threats = "".join(f"<tr><td>{_e(c['control'])}</td><td class=n>{c['count']}</td><td class=n>{c['block']}</td><td class=n>{c['redact']}</td><td class=n>{c['require_approval']}</td></tr>" for c in stats["top_controls"]) or "<tr><td colspan=5 class=muted>No findings in this window.</td></tr>"
    gaps = "".join(f"<li><b>{_e(r['id'])} {_e(r['name'])}</b>: {_e(STATUS_LABEL.get(r['status'], r['status']))}. {_e(r.get('note') or '')}</li>" for r in coverage["risks"] if r["status"] != "covered")
    reload = policy.get("reload") or {}
    reload_line = "last reload OK" if reload.get("status") == "ok" else f"<span class=bad>last reload rejected: {_e((reload.get('error') or {}).get('message'))}</span>"
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8><title>Bouncer summary</title><style>{CSS}</style></head><body>
<h1>Bouncer: AI control layer summary</h1>
<div class=muted>Window {_e(stats['window'])}, {_when(stats['from'])} to {_when(stats['to'])}. Policy {_e(policy['version'])} (profile {_e(policy['profile'])}, mode {_e(policy['mode'])}, fail {_e(policy['fail_mode'])}); {reload_line}.</div>
<h2>Decisions</h2>
<div class=grid>
<div class=kpi>Requests<b>{n}</b></div>
<div class=kpi>Allowed<b>{allowed}</b>{allowed_pct}{logged}</div>
<div class=kpi>Redacted<b>{t['redact']}</b>{pct('redact')}</div>
<div class=kpi>Held for approval<b>{t['require_approval']}</b>{pct('require_approval')}</div>
<div class=kpi>Blocked<b>{t['block']}</b>{pct('block')}</div>
</div>
<h2>Threats by control</h2>
<table><tr><th>Control</th><th class=n>Findings</th><th class=n>Blocked</th><th class=n>Redacted</th><th class=n>Approval</th></tr>{rows_threats}</table>
<h2>Spend vs budget (today, USD)</h2>
<table><tr><th>Team</th><th class=n>Spent</th><th class=n>Budget per day</th><th>State</th></tr>{rows_budget}</table>
<div class=muted>{_e(budgets.get('note'))}</div>
<h2>Performance</h2>
<p>Time added by Bouncer per request: p50 {_ms(ov.get('p50'))}, p95 {_ms(ov.get('p95'))} over {_e(ov.get('n'))} requests (the p95 includes the T2 judge on escalated requests). T2 judge escalation rate {stats['t2']['escalation_rate'] * 100:.1f}% ({stats['t2']['escalations']} calls).</p>
<h2>Posture</h2>
<p>Score <b>{posture['score']}/100</b> ({_e(posture['formula'])}): {posture['covered']} of {posture['total']} OWASP LLM 2025 and Agentic 2026 risks covered, {posture['partial']} partial, {posture['not_covered']} not covered. Controls enabled: {posture['controls']['enabled']} of {posture['controls']['total']} ({posture['controls']['monitor']} in monitor mode).</p>
<p>Known gaps:</p><ul>{gaps}</ul>
</body></html>"""
