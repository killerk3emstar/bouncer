# Judge (T2 semantic control)

The judge answers typed questions about a redacted agent state with a probability for every allowed option.
It does not generate text, so the answer always fits the schema and policy thresholds apply directly.
The gateway calls it only for escalations (T1 grey zone, non-English text, side-effect tool calls).

Measurements and the go/no-go decision: `reports/judge_go_no_go.md`.

## Run

```
uv run python -m judge.server                          # 127.0.0.1:8701, backend from JUDGE_BACKEND (default clef-mlx)
JUDGE_BACKEND=ollama-guard uv run python -m judge.server
JUDGE_BACKEND=fake uv run python -m judge.server        # deterministic heuristics, no model
```

| Variable | Default | Meaning |
|---|---|---|
| `JUDGE_BACKEND` | `clef-mlx` | `clef-mlx` (Apple Silicon), `ollama-guard`, `fake` |
| `CLEF_MLX_PATH` | `models/clef-flash-mlx-4bit` | local MLX checkpoint (`make models`) |
| `JUDGE_MAX_TOKENS` | `1536` | prompt token cap for Clef; longer UNTRUSTED_CONTENT is cut in the middle |
| `OLLAMA_URL` | `http://localhost:11434` | for `ollama-guard` |
| `OLLAMA_GUARD_MODEL` | `llama-guard3:1b` | for `ollama-guard` |
| `JUDGE_MAX_QUEUE` | `16` | queued requests above this get 503 `busy` |
| `JUDGE_HOST`, `JUDGE_PORT` | `127.0.0.1`, `8701` | bind address |

The model loads once in the background and is warmed up with one call. Every model call runs on one worker
thread, so requests are served one at a time in arrival order.

## HTTP API

`POST /v1/decide`

```json
{"state": {"USER_REQUEST": "...", "UNTRUSTED_CONTENT": "...", "PROPOSED_ACTION": {"tool": "mail.send", "arguments": {}}},
 "questions": {"injection": {"type": "noul", "instructions": "..."},
               "goal_alignment": {"type": "score", "instructions": "...",
                                  "criteria": {"aligned": "...", "unclear": "...", "misaligned": "..."}}}}
```

`state` may also be a plain string. Response:

```json
{"answers": {"injection": {"yes": 0.91, "no": 0.09},
             "goal_alignment": {"aligned": 0.05, "unclear": 0.09, "misaligned": 0.86}},
 "backend": "clef-mlx", "model": "clef-flash-mlx-4bit", "latency_ms": 1430.2,
 "input_tokens": 612, "truncated": false}
```

Answer keys: `noul` -> `yes`/`no`; `score` with named criteria -> the names in the given order; `score` with a
list -> `"0"`, `"1"`, ...; `choice` -> the criteria keys. Probabilities sum to 1 per question.
`input_tokens` and `truncated` are additions to the interface above; `truncated: true` means the judge saw only the
head and tail of a long UNTRUSTED_CONTENT, so a "no" is weaker evidence (the gateway sends untrusted content longer than
2,000 characters in overlapping windows, so this is rare).

Errors: `{"error": {"type": "judge_error", "code": ..., "message": ...}}` with 422 `invalid_questions`,
413 `state_too_large`, 503 `loading` / `backend_unavailable` / `busy`, 502 `backend_error`.

`GET /health`: `status` (`loading` | `ok` | `error`), `backend`, `model`, `loaded`, `load_ms`, `warmup_ms`, `error`,
`queue`, `served`, `failed`, `latency_ms_p50`, `latency_ms_p95`, `info` (Clef: `path`, `max_tokens`, `load_ms`,
`peak_memory_mb`, `active_memory_mb`). HTTP 503 when `status` is `error`.

## Client for the gateway

```python
from judge.client import JudgeClient

client = JudgeClient.from_policy(policy["judge"])            # or JudgeClient(url, backend, timeout_ms, cache_ttl_seconds, max_concurrency)
result = await client.decide(state, policy["judge"]["questions"], reason="side_effect_tool")
if result.error:            # timeout | unavailable | bad_response | bad_request | backend_error | disabled
    ...                      # apply fail_mode
elif result.p("injection", "yes") > threshold:
    ...
audit_event["judge"] = result.to_audit()
```

`JudgeResult` fields: `invoked`, `reason`, `backend`, `answers`, `latency_ms`, `cached`, `error`, plus `model`,
`detail` (human-readable error), `input_tokens`.

- Never raises for network, HTTP or backend errors.
- `timeout_ms` bounds the whole call, including the wait for a concurrency slot.
- `max_concurrency` limits calls in flight; identical concurrent requests share one call.
- TTL LRU cache keyed by sha256 of the canonical JSON of (state, questions); errors are not cached.
- `backend="fake"` runs `FakeBackend` in-process (no HTTP, no model) for `make test`. Script answers with
  `client.fake.script({"injection": {"yes": 0.97, "no": 0.03}})`, optionally `when=lambda state: ...`, or pass
  `fake=FakeBackend(...)`.
- `backend="none"` returns `invoked=False, error="disabled"` without calling anything.

## Backends

- `clef-mlx`: Clef-Flash (Cloudflare, Apache-2.0) as converted to MLX 4-bit by TrevorJS. The record encoding and
  joint head are vendored in `backends/clef_port.py` with attribution. All questions are scored jointly in one
  prefill. Chat-template control tokens in the state are broken up before tokenization.
- `ollama-guard`: Llama Guard 3 through Ollama, one call per question with a custom category; P(unsafe) from the
  first token's log-probabilities. A content-safety model, not an injection detector; see the report for numbers.
- `fake`: transparent keyword heuristics (`backends/fake.py`), deterministic, used for tests and as a baseline.

## Evaluation

```
uv run python -m judge.testdata.build_labeled          # regenerate judge/testdata/labeled.jsonl (102 cases)
uv run python -m judge.evaluate --backend fake
uv run python -m judge.evaluate --url http://127.0.0.1:8701 --out reports/judge_eval_clef-mlx.json
uv run python -m judge.bench --url http://127.0.0.1:8701 --sizes 300 1000 --runs 12
uv run pytest tests/unit/judge                          # offline, no models
```
