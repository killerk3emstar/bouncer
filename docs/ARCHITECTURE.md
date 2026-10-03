# Bouncer architecture

Bouncer is a gateway that sits between AI agents and everything they call: models (OpenAI-compatible API), MCP tool servers, and other services that ask it for a decision (`POST /v1/guard/check`). Every call passes one decision pipeline driven by one policy file.

## Components

```mermaid
flowchart LR
  subgraph Clients
    A1[Agent using the OpenAI SDK]
    A2[MCP client]
    A3[Any service / other agent]
  end
  subgraph GW["Bouncer gateway :8700 (FastAPI, stateless per request)"]
    AUTH[1 auth: API key to principal, model and tool allowlists]
    BUD[2 budgets, rate limits, loop breaker]
    NORM[3 normalization: NFKC, invisible and tag chars, homoglyphs, base64/hex/url decode]
    T0[4 T0 deterministic controls]
    T1[5 T1 injection classifier, ONNX on CPU]
    T2C[6 T2 judge client: cache, concurrency limit, timeout, fail mode]
    DEC[7 decision: allow / log / redact / require_approval / block]
    FWD[8 forward, stream with holdback, scan output and tool calls]
    ACC[9 cost accounting, audit event, metrics]
    POL[(policy/bouncer.yaml, hot reload)]
    FEED[(signed signature feed)]
    STORE[(store: budgets, sessions, approvals, MCP pins)]
    AUD[(audit JSONL, SHA-256 chain)]
  end
  J["judge :8701 (Clef-flash MLX on Apple Silicon / Llama Guard via Ollama / fake)"]
  U1[Ollama :11434, local models]
  U2[simulated commercial API :8702]
  M[demo MCP server :8703]
  D[dashboard /ui and /api, /metrics]

  A1 -->|/v1/chat/completions| AUTH
  A2 -->|/mcp| AUTH
  A3 -->|/v1/guard/check| AUTH
  AUTH --> BUD --> NORM --> T0 --> T1 --> T2C --> DEC --> FWD --> ACC
  T2C -->|escalations only, redacted| J
  FWD --> U1
  FWD --> U2
  FWD --> M
  POL -.-> DEC
  FEED -.-> T0
  STORE -.-> BUD
  ACC --> AUD
  AUD --> D
```

## Request flow (OpenAI proxy)

1. **Authenticate.** `Authorization: Bearer <key>` maps to a principal (agent) with a team, a data clearance, allowed models and allowed tools. Unknown key: HTTP 401. Model outside the allowlist: 403. An agent calling for another agent sends `X-Bouncer-On-Behalf-Of: <principal>` (OpenAI proxy and guard API); this is allowed only when `principals.<caller>.may_act_for` lists the target, and the request then runs as the target with the intersection of both agents' models and tools, the lower data clearance and the stricter profile, with the caller recorded as `principal.via` in the audit event. Otherwise: 403 `auth.delegation_not_allowed`.
2. **Budgets and loops.** Team USD per day, session USD, tokens per minute, local GPU seconds per hour, session step limit, input size. A spent paid budget downgrades the request to the local model (`budgets.on_exceed.downgrade_to`); a spent hard limit returns 429. An open loop breaker (after identical tool calls) returns 429 until the cooldown ends.
3. **Segmentation.** The request is split into segments: system prompt, user messages, tool results (with the tool name resolved from `tool_call_id`), tool definitions. Tool results from `untrusted_source_tools` are untrusted; results from `sensitive_source_tools` mark the session as holding sensitive data.
4. **Normalization.** Invisible characters and Unicode tag characters are removed from what is forwarded; a normalized view (NFKC, homoglyphs folded, leetspeak folded, spaced letters joined) and decoded views (base64, hex, URL encoding; ROT13 and reversed text when the result reads more like English) are scanned by every control.
5. **T0 deterministic controls** (always on; measured p50 0.3 ms for a short prompt and 2.6 ms for a 2 KB prompt, `reports/bench.md`): secrets, PII with checksum validation, injection heuristics (EN, PL, DE, chat-template tokens), signatures from the signed feed, supply chain rules. Results are cached per (policy version, profile, segment hash), so a long conversation is not rescanned on every turn.
6. **T1 classifier** on new untrusted segments (user messages, tool results, tool definitions, content saved with a memory tool): `protectai/deberta-v3-base-prompt-injection-v2` (ONNX, CPU). Score at or above `block_above` blocks (the shipped policy sets it to 1.0, so T1 never blocks on its own); between `escalate_above` and `block_above` escalates to T2. The model is English-only, so non-English text is escalated to T2 instead of being trusted or blocked on a meaningless score.
7. **T2 judge** only on escalations: grey-zone T1 scores, non-English text, and every side-effect tool call (goal alignment and exfiltration questions). The judge returns probabilities for options defined in the policy (`judge.questions`); thresholds in the policy map them to block or require_approval. The judge sees only redacted content and runs on our own hardware (`judge.allow_external: false` is enforced by the schema).
8. **Decision.** The strongest action wins: allow < log < redact < require_approval < block. `mode: monitor` (global or per control) records what would have happened and enforces nothing. The `permissive` profile records non-critical findings as log; `strict` tightens thresholds and requires approval for every side effect.
9. **Forward and check the response.** Redactions are applied before the upstream sees the request (a secret inside a tool definition cannot be rewritten in place, so it blocks the request); a canary token is added to the system prompt. The model's text is scanned (secrets, PII, markdown image/link exfiltration, HTML, canary leak), including `reasoning`, `reasoning_content` and `refusal` fields in plain responses; in streams the reasoning fields are dropped because they cannot be checked incrementally. A legacy `function_call` answer gets the same checks as a tool call (in a stream it is blocked). The model's tool calls are checked before the agent receives them: tool allowlist, argument rules (recipient domains, forbidden fields such as BCC, amount limits), signatures and secrets in arguments, lethal trifecta (session read untrusted content and sensitive data and now sends data out), identical-call loops, and the T2 goal-alignment check; the content of a memory write (`tool_governance.memory_write_tools`) also gets the injection checks. Streaming responses are released only up to a safe boundary (at least 64 characters behind the newest text, never inside a word, an unclosed markdown link or image, an HTML tag or a PEM block), so redaction works across chunk boundaries; tool calls are buffered until their arguments are complete. The response headers of a stream are sent before the output is checked, so they carry the input decision; the final chunk carries the final decision in an extra `bouncer` field (`action`, `trace_id`, `findings`), and a block during the stream ends it with an `error` event.
10. **Account and audit.** Cost from token usage and the policy's prices (local models: GPU seconds times an internal rate), one audit event per decision with the full trace, Prometheus metrics.

## Human approval

`require_approval` creates a request (dashboard, `GET/POST /api/approvals`). The agent receives HTTP 403 with `approval_id`. After approval, exactly the same call (SHA-256 of tool name and canonical arguments) by the same agent in the same session is allowed once, within `approvals.ttl_seconds` after the decision; the approval is then marked `used`. Any change to the arguments needs a new approval. The agent can read the status of its own request (`GET /v1/approvals/{id}` with its agent key) but cannot decide it: deciding needs the admin token.

## Policy as code

One YAML file, validated by a pydantic schema that rejects unknown keys. The watcher reloads it within about a second of a save (measured 0.12 s); an invalid file is rejected with a line number and the previous version stays active. Every version is kept in memory with a unified diff and written to the audit log (`policy.reloaded`, `policy.reload_failed`). A control removed from the file is disabled, and the dashboard shows it as disabled.

## Signature feed

`signatures/feed.json` is signed with ed25519 (`feed.json.sig`; the public key file `signatures/feed.pub` is named in the policy, `controls.signatures.public_key`). The gateway checks the feed file about once a second and reloads it when it changes (a feed served from a URL: every `refresh_seconds`); a feed with a missing or invalid signature, or a validly signed feed with a lower version than the active one (rollback), is rejected and the previous version stays active. Each signature carries its source references.

## Audit

`data/audit.jsonl`: one JSON line per decision, with `seq`, `prev_hash` and `hash = sha256(prev_hash + canonical event)`; `data/audit.jsonl.head` holds the newest `seq` and `hash`. Only redacted excerpts and masked evidence are stored. `make verify-audit` reports the first modified, deleted or reordered line, and lines removed from the end. Exports: `GET /api/export/audit.jsonl` and `.csv` with the dashboard filters.

## Scaling

- The gateway keeps no per-request state. Shared counters (budgets, sessions, approvals, MCP pins) live behind the `Store` interface, in process memory in this build, so it runs as one node. Several replicas behind a load balancer would need a Redis-backed `Store` (atomic increments, sorted sets for time windows); that is designed, not built.
- The judge is a separate service with the `POST /v1/decide` interface: Clef on MLX on a Mac, Llama Guard via Ollama elsewhere. A GPU server for the same model would implement the same interface; it is not built here.
- The policy is loaded from a file (a Git checkout works the same way; loading from a URL is not built); the version hash identifies it in every audit event.
- Audit events can be shipped to a SIEM by tailing the JSONL file; there is no stdout or syslog output in this build.
