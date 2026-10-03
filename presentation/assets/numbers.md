# Bouncer: measured numbers for the slides

Every number below was measured on an Apple M4 Pro (48 GB, macOS 27.0.1, Python 3.12.11), on 2026-10-04 between 00:00 and 02:00, with the machine shared with another project. Source file for each number in brackets.

## Tests (slide: proof)

- `make test`: 1099 tests in about 10 to 11 s, no network, no models (15 to 20 s on the first run of a fresh clone) [run `make test`; reports/tests/summary.md].
  - 437 YAML cases that run through the full gateway (auth, budgets, loops, tool governance and lethal trifecta, secrets, PII, obfuscation, prompt injection, output safety and canary, signatures, supply chain, memory poisoning, agent delegation, red team, benign hard negatives).
  - The rest are unit tests (gateway mechanics, policy reload, audit chain, controls, judge, T1, signatures, MCP gateway, demo).
- `make test-live` against the running stack with the real T1 classifier and the Clef judge: 0 failed (last run: 361 passed and 79 skipped before the delegation cases were wired to the live runner; skipped = cases that need scripted judge answers or policy patches).
- `make demo`: 12 of 12 scripted attack scenarios pass, including an MCP rug pull.
- Docker: `docker compose run --rm tests` passes the same suite in a Linux container (one Apple-only test skipped).

## Detection quality (slide: proof)

`make eval-full`, 394 texts: our bank-operations set (278 prompts, EN/PL/DE, direct, indirect and jailbreak attacks plus hard benign prompts) and the `deepset/prompt-injections` test split (116) [reports/eval_layers.md].

| Layer | Precision | Recall | False-positive rate | Latency p50 / p95 |
|---|---|---|---|---|
| T0 deterministic only | 98.7% | 39.7% | 0.5% | 0.4 / 0.8 ms |
| T1 classifier alone (DeBERTa, threshold 0.5) | 78.0% | 69.6% | 19.0% | 10.5 / 20.4 ms |
| Full pipeline T0 + T1 + T2 | 98.4% | 64.4% | 1.0% | 13.6 / 674 ms |

- On the bank-operations set alone: 117 of 134 attacks stopped (87%), 2 false positives in 144 benign prompts (1.4%).
- On `deepset/prompt-injections`: 8 of 60. Most items there are role-play or topic-change requests that our judge questions do not count as attacks on a bank assistant. We report it anyway.
- The judge question for user messages was refined after this run; measured separately on 246 user prompts it gives 75.5% recall with 0 false positives at the block threshold (it was 73.5% with 1 false positive).

## Red team (slide: robustness)

82 attacks in 22 technique families (instruction override in 8 languages, spaced letters, leetspeak, homoglyphs, zero-width characters, base64, ROT13, Unicode tag smuggling, indirect injection in tool results, tool poisoning, DAN / developer mode / Skeleton Key, Policy Puppetry, chat-template tokens, prompt leaks, secrets in JSON / URLs / base64 / split strings, PII, markdown and HTML exfiltration, reverse shells, metadata SSRF, pickle, trust_remote_code, BCC, transfer limits) and 46 hard benign prompts, through the real pipeline with the real T1 [reports/redteam.md]:

- 82 of 82 attacks stopped, 46 of 46 benign prompts allowed (after fixing the 4 gaps the first pass found).

## The AI judge (slide: three layers)

Clef-flash (Cloudflare, Apache 2.0), MLX 4-bit, one forward pass answers several questions with probabilities, no text generation [reports/judge_go_no_go.md]:

- On 102 hand-labeled cases (EN, PL): injection AUC 0.996, goal alignment AUC 0.978, exfiltration AUC 0.974; no false positive on 33 benign tool results containing imperative text.
- Llama Guard 3 1B on the same cases: 0.72 / 0.58 / 0.74.
- Latency: 1.1 to 2.0 s per decision for states up to about 300 tokens; 3.3 to 4.1 s at about 1000 tokens (grows linearly, about 400 tokens per second). Memory 6.1 GB.
- How often the judge runs depends on the traffic (measured on our benign bank-operations prompts, real T1): 1 of 50 ordinary English prompts (2%), 14 of 38 hard English prompts (37%), and nearly every Polish or German prompt (49 of 50 Polish), because T1 only reads English and non-English text goes to the judge by design (`prompt_injection.escalate_non_english`, can be switched off). A short Polish message costs about 0.6 s of judge time (live test). Every side-effect tool call also goes to the judge (goal alignment). The dashboard shows the escalation rate live.

## Cost of the checkpoint (slide: performance)

`make bench`, simulated model API, one gateway worker, 200 requests per scenario [reports/bench.md]:

- Gateway overhead p50: 10.8 ms for a short prompt, 83 ms for a 2 KB prompt; 0.2 ms when the same prompt repeats (cached). T1 is 88 to 95% of it; T0 is 0.3 to 2.6 ms.
- Throughput with T1: about 187 requests per second at 8 to 32 concurrent clients, p95 98 ms at 32 clients. Without T1: about 620 requests per second.
- Allowing 3 concurrent T1 inferences instead of 1 doubled throughput (95 to 187 req/s) and cut p95 at 32 clients from 2.2 s to 98 ms.
- MCP gateway: about 5 to 8 ms overhead per tool call without the judge (one-off measurements on the live stack, not in a report); about 1.9 s when the judge is called for a side-effect tool.

## T1 classifier facts (slide: three layers, honest limits)

[reports/t1.md, reports/eval.md]

- 15 to 17 ms for a short message, about 0.5 s for a 1000-token page, on CPU.
- English only. On our bank-operations benign prompts it flags 26% at threshold 0.5 (Polish hard negatives up to 67%), and it is at chance level on indirect injections in tool results (AUC 0.48 on the judge's labeled set). That is why T1 never blocks on its own in the default profile; it routes text to the judge.

## Security bugs we found in our own code and fixed (slide: optional, credibility)

All found by tests, the red team or a dedicated security review during the night, each fixed with a regression test (full list with status: reports/security_review.md). Examples:

- the audit excerpt could contain a secret from the request (now every secret and PII value is masked whatever the action);
- tool-call arguments with secrets reached the audit record;
- the AI layers received text before redaction;
- the dashboard self-test overwrote the gateway's API keys;
- without an admin token an agent on the same host could approve its own held call (the admin API now always needs a token, agents can only poll their own approval);
- approvals could be reused within their window (now single-use, bound to agent and session);
- MCP results wrapped in embedded resources were not scanned;
- an older, validly signed signature feed could replace a newer one (rollback now refused).

## Screenshots

`dashboard_*.png` and `report_summary.png` in this folder (1440 px wide, 2x). Regenerate with `uv run --with playwright python scripts/screenshots.py` against a running stack after `make demo`.
