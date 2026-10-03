"""Latency budget for T0 text controls: prepare() + secrets + pii + injection heuristics + output safety."""

from __future__ import annotations

import statistics
import time

from bouncer.controls.normalize import prepare
from bouncer.core import Segment

from ._util import controls, ctx, policy_doc

MIXED = (
    "Hi team, please review the Q3 summary below and prepare the board pack by Friday.\n"
    "Revenue grew 4.2% to 18.3M PLN; costs were flat. Contact jan.kowalski@bank.example or +48 600 123 456.\n"
    "Klient prosi o zestawienie transakcji z ostatnich 3 miesiecy dla konta PL61 1090 1014 0000 0712 1981 2874.\n"
    "Deploy log: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE region=eu-central-1 build 3f2a9c8e1b4d5f6a7b8c9d0e1f2a3b4c\n"
    "See the dashboard ![chart](https://bank.example/c.png) and docs at https://docs.bank.example/q3.\n"
    "Notes: the forecast assumes stable FX rates, no new hires in Q4, and the migration finishing in November.\n"
) * 4


def _measure(text: str, role: str, direction: str, n: int = 300) -> tuple[float, float]:
    obf = policy_doc().controls.obfuscation
    cs = list(controls().values())
    c = ctx("internal", canary="bc-7f3a9c11d2e4")
    seg = Segment(text, direction, role)
    times = []
    for _ in range(n):
        t = time.perf_counter()
        clean, views, _ = prepare(seg, obf)
        s2 = Segment(clean, direction, role)
        for control in cs:
            if control.applies_to(s2):
                control.scan(s2, views, c)
        times.append((time.perf_counter() - t) * 1000)
    times.sort()
    return statistics.median(times), times[int(len(times) * 0.95) - 1]


def test_t0_controls_p95_under_budget_for_2kb_segment():
    text = MIXED[:2048]
    assert len(text) == 2048
    _measure(text, "user", "input", n=20)  # warm-up
    p50_in, p95_in = _measure(text, "user", "input")
    p50_out, p95_out = _measure(text, "assistant", "output")
    print(f"\nT0 latency, 2 KB mixed segment: input p50={p50_in:.3f} ms p95={p95_in:.3f} ms; "
          f"output p50={p50_out:.3f} ms p95={p95_out:.3f} ms")
    assert p95_in < 5.0 and p95_out < 5.0
