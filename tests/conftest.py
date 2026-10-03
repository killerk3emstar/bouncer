"""Test session setup and the per-control summary written to reports/tests/."""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)  # policy and signature paths are relative to the repo root
os.environ.setdefault("BOUNCER_WATCH", "0")

_results: list[dict] = []
_t0 = time.time()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):  # noqa: ANN001, ANN201
    outcome = yield
    rep = outcome.get_result()
    if rep.when != "call" and not (rep.when == "setup" and rep.failed):
        return
    props = dict(item.user_properties)
    _results.append(
        {
            "nodeid": item.nodeid,
            "outcome": rep.outcome,
            "control": props.get("control") or _area(item.nodeid),
            "kind": props.get("kind", ""),
            "duration_s": round(rep.duration, 4),
        }
    )


def _area(nodeid: str) -> str:
    parts = nodeid.split("/")
    if len(parts) > 2 and parts[1] == "unit":
        return f"unit:{parts[2]}"
    return "other"


def pytest_sessionfinish(session, exitstatus):  # noqa: ANN001, ANN201
    if not _results:
        return
    out = ROOT / "reports" / "tests"
    out.mkdir(parents=True, exist_ok=True)
    by = defaultdict(lambda: {"passed": 0, "failed": 0, "skipped": 0, "allow_cases": 0, "block_cases": 0})
    for r in _results:
        b = by[r["control"]]
        b[r["outcome"]] = b.get(r["outcome"], 0) + 1
        if r["kind"]:
            if r["kind"] in ("allow", "known_gap", "log"):
                b["allow_cases"] += 1
            else:
                b["block_cases"] += 1
    total = len(_results)
    passed = sum(1 for r in _results if r["outcome"] == "passed")
    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "duration_s": round(time.time() - _t0, 2),
        "total": total,
        "passed": passed,
        "failed": sum(1 for r in _results if r["outcome"] == "failed"),
        "by_control": dict(sorted(by.items())),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    lines = [
        "# Test summary",
        "",
        f"{passed}/{total} passed in {summary['duration_s']} s ({summary['generated_at']}).",
        "",
        "| Control / area | Passed | Failed | Allow cases | Block/redact cases |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, b in summary["by_control"].items():
        lines.append(f"| {name} | {b['passed']} | {b['failed']} | {b['allow_cases']} | {b['block_cases']} |")
    (out / "summary.md").write_text("\n".join(lines) + "\n")
