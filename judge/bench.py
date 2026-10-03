"""Judge latency for states of a given size (all policy questions in one request).

    uv run python -m judge.bench --url http://127.0.0.1:8701 --sizes 300 1000 --runs 12
    uv run python -m judge.bench --backend fake

State size is measured in Clef tokens of the rendered state (tokenizer.json of the checkpoint);
the full prompt adds the system frame and the question schema (reported as input_tokens).
Each size gets one unmeasured warm-up call, then ``--runs`` measured calls with a small
variation at the start of each field, so that no layer can serve a cached answer or reuse a
cached prompt prefix (Ollama keeps one).
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

from judge.evaluate import Runner, pct
from judge.questions import load_policy_questions

PARAGRAPHS = [
    "Acme Payments processes card and SEPA payments for mid-sized banks in the EU. Card processing costs 0.20% per "
    "transaction with no monthly fee; SEPA credit transfers cost EUR 0.05 each.",
    "Settlement happens on T+1 for cards and same day for SEPA Instant. Chargebacks are handled through the merchant "
    "portal, where disputes can be tracked and evidence uploaded within 14 days.",
    "Our data centres are located in Frankfurt and Dublin. All cardholder data is stored encrypted at rest with keys "
    "managed in hardware security modules, and access is logged and reviewed monthly.",
    "Service level: 99.95% monthly availability for the payment API, measured per calendar month. Credits apply when "
    "availability falls below the target, as described in the service agreement.",
    "Onboarding takes about three weeks and includes a security questionnaire, a test integration in the sandbox, and a "
    "go-live review with the bank's operations team.",
    "Volume discounts start at one million transactions per month. Contact the account team for a quote that reflects "
    "your expected mix of card, SEPA and instant payments.",
    "Fraud screening uses device fingerprinting, velocity checks and a rules engine that the bank can configure. Alerts "
    "are delivered by webhook and in the daily report.",
    "Reporting includes daily settlement files, monthly invoices and an API for transaction-level reconciliation. Files "
    "are delivered over SFTP or through the portal.",
]


def build_state(target_tokens: int, count_tokens) -> dict:
    state = {
        "USER_REQUEST": "Summarize the vendor page for Acme Payments and reply to their sales team with our questions about fees.",
        "UNTRUSTED_CONTENT": "web.fetch https://acme-payments.io/overview\n\n",
        "PROPOSED_ACTION": {"tool": "mail.send", "arguments": {"to": "sales@acme-payments.io", "subject": "Fees",
                                                               "body": "Do you offer volume discounts above 1 million transactions per month?"}},
    }
    i = 0
    while count_tokens(state) < target_tokens:
        state["UNTRUSTED_CONTENT"] += PARAGRAPHS[i % len(PARAGRAPHS)] + "\n"
        i += 1
    return state


def token_counter():
    path = Path("models/clef-flash-mlx-4bit/tokenizer.json")
    if path.exists():
        from tokenizers import Tokenizer

        tok = Tokenizer.from_file(str(path))
        return lambda s: len(tok.encode(json.dumps(s, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
                                        add_special_tokens=False).ids)
    return lambda s: len(json.dumps(s)) // 4


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="fake")
    ap.add_argument("--url")
    ap.add_argument("--sizes", type=int, nargs="+", default=[300, 1000])
    ap.add_argument("--runs", type=int, default=12)
    ap.add_argument("--policy", default="policy/bouncer.yaml")
    ap.add_argument("--out")
    args = ap.parse_args()

    from judge.backends.base import normalize_questions

    questions = normalize_questions(load_policy_questions(args.policy))
    runner = Runner(None if args.url else args.backend, args.url)
    count = token_counter()
    report = {"backend": runner.name, "model": runner.model, "questions": list(questions), "sizes": {}}
    for size in args.sizes:
        base = build_state(size, count)
        runner.decide(base, questions)  # warm-up for this shape
        lat, wall, toks = [], [], []
        for r in range(args.runs):
            # vary the start of every field so no backend can reuse a cached prompt prefix
            state = {**base, "USER_REQUEST": f"[ticket {r}] " + base["USER_REQUEST"],
                     "UNTRUSTED_CONTENT": f"[fetch {r}] " + base["UNTRUSTED_CONTENT"]}
            t0 = time.perf_counter()
            _answers, latency, tokens = runner.decide(state, questions)
            wall.append((time.perf_counter() - t0) * 1000)
            lat.append(latency)
            toks.append(tokens)
        row = {"state_tokens": count(base), "input_tokens": toks[0], "runs": args.runs,
               "p50_ms": round(pct(lat, 0.5), 1), "p95_ms": round(pct(lat, 0.95), 1),
               "mean_ms": round(statistics.mean(lat), 1), "min_ms": round(min(lat), 1), "max_ms": round(max(lat), 1),
               "client_wall_p50_ms": round(pct(wall, 0.5), 1)}
        report["sizes"][str(size)] = row
        print(f"state ~{size} tokens (actual {row['state_tokens']}, prompt {row['input_tokens']}): "
              f"p50 {row['p50_ms']} ms, p95 {row['p95_ms']} ms, min {row['min_ms']}, max {row['max_ms']}", file=sys.stderr)
    report["health"] = runner.health()
    print(json.dumps({k: v for k, v in report.items() if k != "health"}, indent=1))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
