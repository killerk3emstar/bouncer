"""Run the probe set (scripts/redteam/probes.py) through the gateway and print a report.

Usage: uv run python scripts/redteam/run.py [fake|onnx]
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.redteam.harness import run_all  # noqa: E402
from scripts.redteam.probes import ALL, ATTACKS, BENIGN  # noqa: E402

STOP = {"block", "redact", "require_approval"}


def main() -> None:
    t1 = sys.argv[1] if len(sys.argv) > 1 else "fake"
    results = asyncio.run(run_all(ALL, t1=t1))
    by_id = {r["id"]: r for r in results}

    print(f"=== mode: T1={t1}, judge=fake ===\n")
    show_all = "-v" in sys.argv
    print("--- ATTACKS (must be stopped) ---")
    atk_fail = []
    cat_tot: dict[str, int] = {}
    cat_stop: dict[str, int] = {}
    for p in ATTACKS:
        r = by_id[p["id"]]
        stopped = r["action"] in STOP
        c = p["attack_class"]
        cat_tot[c] = cat_tot.get(c, 0) + 1
        cat_stop[c] = cat_stop.get(c, 0) + (1 if stopped else 0)
        if not stopped:
            atk_fail.append(p["id"])
            print(f"  LEAK {p['id']:<24} [{c}] action={r['action']} findings={','.join(r['findings']) or '-'}")
        elif show_all:
            print(f"  ok   {p['id']:<24} [{c}] action={r['action']:<16} findings={','.join(r['findings']) or '-'}")
    print(f"  stopped {sum(cat_stop.values())}/{sum(cat_tot.values())}")

    print("\n--- BENIGN (must pass) ---")
    ben_fail = []
    for p in BENIGN:
        r = by_id[p["id"]]
        stopped = r["action"] in STOP
        if stopped:
            ben_fail.append(p["id"])
            print(f"  FP   {p['id']:<24} [{p['attack_class']}] action={r['action']} findings={','.join(r['findings']) or '-'}")
    print(f"  passed {len(BENIGN) - len(ben_fail)}/{len(BENIGN)}")

    print("\n--- per attack_class (stopped/total) ---")
    for c in sorted(cat_tot):
        print(f"  {c:<22} {cat_stop[c]}/{cat_tot[c]}")

    print(f"\nATTACK LEAKS: {atk_fail}")
    print(f"BENIGN FALSE POSITIVES: {ben_fail}")


if __name__ == "__main__":
    main()
