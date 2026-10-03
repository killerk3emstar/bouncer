"""Capture dashboard screenshots for the presentation (presentation/assets/).

Needs a running stack (make dev) with some traffic (make demo). Uses Playwright in an ephemeral env:

    uv run --with playwright python -m playwright install chromium   # once
    uv run --with playwright python scripts/screenshots.py [--base http://localhost:8700] [--theme light]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "presentation" / "assets"

VIEWS = [
    ("overview", "#/overview", None),
    ("events", "#/events", None),
    ("controls", "#/controls", None),
    ("coverage", "#/coverage", None),
    ("performance", "#/performance", None),
    ("policy", "#/policy", None),
    ("signatures", "#/signatures", None),
    ("approvals", "#/approvals", None),
    ("playground", "#/playground", None),
]


def pick_trace(base: str, action: str) -> str | None:
    with urllib.request.urlopen(f"{base}/api/events?action={action}&limit=50") as r:  # noqa: S310 (local)
        events = json.load(r)["events"]
    for ev in events:
        if ev.get("findings"):
            return ev["trace_id"]
    return events[0]["trace_id"] if events else None


async def main() -> None:
    from playwright.async_api import async_playwright

    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8700")
    ap.add_argument("--theme", default="light", choices=["light", "dark"])
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    views = list(VIEWS)
    for action in ("require_approval", "block", "redact"):
        tr = pick_trace(args.base, action)
        if tr:
            views.append((f"trace_{action}", f"#/events/{tr}", None))
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        ctx = await browser.new_context(viewport={"width": 1440, "height": 1000}, device_scale_factor=2, color_scheme=args.theme)
        page = await ctx.new_page()
        for name, frag, _ in views:
            await page.goto(f"{args.base}/ui/{frag}")
            await page.wait_for_timeout(2500)
            path = OUT / f"dashboard_{name}.png"
            await page.screenshot(path=str(path), full_page=name not in ("events",) and not name.startswith("trace_"))
            print("wrote", path.relative_to(OUT.parent.parent))
        await page.goto(f"{args.base}/reports/summary")
        await page.wait_for_timeout(800)
        await page.screenshot(path=str(OUT / "report_summary.png"), full_page=True)
        print("wrote presentation/assets/report_summary.png")
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
