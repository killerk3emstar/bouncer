"""T1 latency benchmark: one call per measurement, model loaded and warm.

    uv run python eval/bench_t1.py [--iters 30] [--threads 4]

Cases: single texts of about 50, 300 and 1000 tokens (1000 tokens = 3 overlapping windows), a
batch of 8 short texts and a batch of 8 texts of about 300 tokens. Writes reports/t1_bench.json and
prints a Markdown table. The machine may be shared: the load average before and after is recorded.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bouncer.t1.classifier import OnnxInjectionClassifier  # noqa: E402
from eval.run_eval import hardware, percentile  # noqa: E402

PARAGRAPH = (
    "The operations team reviewed the overnight batch and found that most standing orders were executed "
    "on time. A small number of transfers failed because the beneficiary account was closed or the "
    "reference field was too long. The team contacted the affected customers, corrected the references "
    "and resubmitted the payments before the morning cut-off. Card settlement totals matched the general "
    "ledger, and no unusual activity was reported by the monitoring system. "
)


def text_with_tokens(clf: OnnxInjectionClassifier, n: int) -> str:
    words = (PARAGRAPH * (n // 40 + 2)).split()
    lo, hi = 1, len(words)
    while lo < hi:  # smallest prefix with >= n tokens
        mid = (lo + hi) // 2
        if len(clf._tokenizer.encode(" ".join(words[:mid]), add_special_tokens=False).ids) >= n:
            hi = mid
        else:
            lo = mid + 1
    return " ".join(words[:lo])


def measure(clf: OnnxInjectionClassifier, texts: list[str], iters: int) -> dict:
    for _ in range(3):
        clf.score(texts)
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        clf.score(texts)
        samples.append((time.perf_counter() - t0) * 1000)
    tokens = [len(clf._tokenizer.encode(t, add_special_tokens=False).ids) for t in texts]
    windows = sum(r.windows_scored for r in clf.score_detailed(texts))
    return {
        "texts": len(texts), "tokens_per_text": round(statistics.mean(tokens)), "windows": windows,
        "iters": iters, "p50_ms": percentile(samples, 0.5), "p95_ms": percentile(samples, 0.95),
        "mean_ms": statistics.mean(samples), "min_ms": min(samples),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=30)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--model-path", default=None, help="ONNX model dir (default: env T1_MODEL_PATH or models/deberta-pi-v2/onnx)")
    ap.add_argument("--label", default="ONNX fp32", help="model variant label for the report")
    ap.add_argument("--out", default="t1_bench", help="report name in reports/ (without .json)")
    args = ap.parse_args()

    load_before = os.getloadavg()
    clf = OnnxInjectionClassifier(args.model_path, threads=args.threads)
    t0 = time.perf_counter()
    clf.load()
    load_s = time.perf_counter() - t0

    t50, t300, t1000 = (text_with_tokens(clf, n) for n in (50, 300, 1000))
    cases = {
        "1 text, ~50 tokens": [t50],
        "1 text, ~300 tokens": [t300],
        "1 text, ~1000 tokens (3 windows)": [t1000],
        "batch of 8 texts, ~50 tokens each": [t50 + f" Ref {i}." for i in range(8)],
        "batch of 8 texts, ~300 tokens each": [t300 + f" Ref {i}." for i in range(8)],
    }
    results = {name: measure(clf, texts, args.iters) for name, texts in cases.items()}
    import onnxruntime

    report = {
        "hardware": hardware(),
        "onnxruntime": onnxruntime.__version__,
        "provider": "CPUExecutionProvider",
        "intra_op_threads": args.threads,
        "model": f"protectai/deberta-v3-base-prompt-injection-v2 ({args.label})",
        "model_path": str(clf.model_path),
        "load_and_warmup_seconds": round(load_s, 2),
        "load_average_before": [round(x, 2) for x in load_before],
        "load_average_after": [round(x, 2) for x in os.getloadavg()],
        "python": platform.python_version(),
        "cases": results,
    }
    out = ROOT / "reports" / f"{args.out}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")

    print(f"{report['hardware']}; onnxruntime {report['onnxruntime']} CPU, {args.threads} threads; "
          f"load + warm-up {report['load_and_warmup_seconds']} s; load avg {report['load_average_before']} -> "
          f"{report['load_average_after']}")
    print("| case | tokens/text | windows | p50 ms | p95 ms | mean ms |")
    print("|---|---|---|---|---|---|")
    for name, r in results.items():
        print(f"| {name} | {r['tokens_per_text']} | {r['windows']} | {r['p50_ms']:.1f} | {r['p95_ms']:.1f} | {r['mean_ms']:.1f} |")


if __name__ == "__main__":
    main()
