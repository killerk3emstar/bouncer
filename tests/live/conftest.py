"""Fixtures for the live suite (`make test-live`): a running stack, real T1/T2, real HTTP.

Every test here is marked `live`, so `make test` (pytest -m "not live") deselects them. When the
gateway is not reachable the tests are skipped with the reason, never failed.
"""

from __future__ import annotations

import pytest

from tests.live.helpers import LATENCY_ROWS, LiveStack

_STACK: LiveStack | None = None
_ERROR: str | None = None


@pytest.fixture(scope="session")
def live() -> LiveStack:
    global _STACK, _ERROR
    if _STACK is None and _ERROR is None:
        try:
            _STACK = LiveStack.connect()
        except RuntimeError as exc:
            _ERROR = str(exc)
    if _STACK is None:
        pytest.skip(_ERROR or "live stack unavailable")
    return _STACK


@pytest.fixture(scope="session")
def live_judge(live: LiveStack) -> LiveStack:
    """Skip tests that need the real T2 judge when the stack runs without one."""
    j = live.judge_info
    backend = (j.get("backend") or "").lower()
    if backend in ("fake", "none"):
        pytest.skip(f"the stack's judge backend is '{backend}'; these tests need a real judge (make judge, or the cpu-judge profile)")
    if j.get("healthy") is False:
        pytest.skip(f"judge {backend} at {j.get('url')} is not healthy ({j.get('health') or 'no detail'}); start it with `make judge` "
                    "or `docker compose --profile cpu-judge up -d`")
    return live


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:  # noqa: ANN001
    if not LATENCY_ROWS:
        return
    tr = terminalreporter
    tr.section("Bouncer live: per-layer latency (ms) and decisions")
    if _STACK is not None:
        j = _STACK.judge_info
        tr.write_line(f"gateway {_STACK.url}  policy {_STACK.policy_summary.get('version', '?')}  judge {j.get('backend', '?')} "
                      f"(healthy={j.get('healthy')})  mock {_STACK.mock_url} (reachable={_STACK.mock_ok})")
    tr.write_line(f"{'test':<46} {'action':<16} {'T0':>6} {'T1':>7} {'T2':>8} {'upstr':>7} {'ovhd':>8} {'T1 max':>7}  judge / findings")
    for r in LATENCY_ROWS:
        def f(x: object, nd: int = 1) -> str:
            return "-" if x is None else f"{float(x):.{nd}f}"
        tr.write_line(
            f"{r['test'][:46]:<46} {str(r['action'])[:16]:<16} {f(r['t0'], 2):>6} {f(r['t1']):>7} {f(r['t2']):>8} {f(r['upstream']):>7} "
            f"{f(r['overhead']):>8} {f(r['t1_max_score'], 3):>7}  {r['judge']} | {r['findings']}"
        )
