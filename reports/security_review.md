# Bouncer security review

Read-only review of the gateway, pipeline, controls, judge, MCP gateway and dashboard. Every finding
below was reproduced in-process with `httpx.ASGITransport` (and, for MCP, a temporary gateway on
127.0.0.1:8705) using only synthetic test values: the AWS documentation key `AKIAIOSFODNN7EXAMPLE`,
the test card `4111111111111111`, and `*.example` domains. Harness and checks are under
`scripts/secreview/` (run: `PYTHONPATH=.:scripts/secreview uv run python scripts/secreview/checks.py`).

The code changed several times during the review (the coordinator was fixing issues in parallel).
Findings are split into **open** (reproduced on the latest tree), **fixed during the review**
(reproduced, then verified fixed, with the fixing commit/area), and **held up** (checked, no defect).

Repo HEAD at the final pass: `879487c` plus uncommitted edits in the working tree.

---

## Status after fixes (2026-10-04 02:10, lead)

All findings in this report were fixed after the review, each with a regression test in `make test`, except the items marked open.

| Finding | Status | Test |
|---|---|---|
| HIGH-1 MCP non-text content blocks not scanned | fixed: embedded text resources scanned and redacted, image/audio/blob blocks withheld | tests/unit/mcp `test_embedded_resource_in_result_is_scanned` |
| MCP blocked-result excerpt raw | fixed: excerpt goes through `Engine.audit_mask` | tests/unit/mcp `test_blocked_result_excerpt_is_masked` |
| Content parts with a non-standard `type` forwarded unscanned | fixed: any part with a `text` field is scanned | `test_content_parts_of_any_type_are_scanned` |
| CSV formula injection | fixed | `test_csv_neutralizes_formulas` |
| Rotating `X-Bouncer-Session` evades per-session limits | open by design: the client chooses its session id; sessions are now namespaced per agent, and the per-team limits (USD per day, tokens per minute, GPU seconds) are the hard backstop. Documented in docs/THREAT_MODEL.md | `loops-breaker-does-not-cross-agents` |
| Audit tail truncation | fixed: `<audit>.head` sidecar with the newest seq and hash (deleting both files is still possible; ship the log to a SIEM) | `test_removed_tail_lines_are_detected` |
| `judge.allow_external` userinfo bypass | fixed: `urlsplit(url).hostname` | `test_external_judge_check_cannot_be_bypassed_with_userinfo` |
| Feed rollback to an older signed version | fixed | tests/unit/signatures `test_rollback_to_older_signed_feed_is_refused` |
| Items "fixed during the review" below | fixed | see the tests named in each item and tests/unit/core/test_gateway.py |
| Judge starvation by one agent, MCP pins in memory, self-reported MCP server name | open, documented | |

---

## Open findings (as found during the review)

### HIGH-1 MCP tool results inside non-text content blocks are never scanned
`bouncer/gateway/mcp_gateway.py:658-663` (`_inspect_result`)

`_inspect_result` collects text to scan only from `TextContent` blocks (`texts`) and from string
leaves of `structured_content` (`leaves`). An MCP tool may also return its payload in an
`EmbeddedResource` block (`TextResourceContents.text`) — and image/audio/blob blocks. That text is
neither scanned (secrets, PII, injection, signatures), nor redacted, nor does it mark session taint.
A malicious or compromised upstream MCP server (the exact threat the pinning/poisoning story targets)
bypasses the whole result layer by wrapping its output in a resource block.

Reproduction (`scripts/secreview/mcp_checks.py`, a `kb.search` tool returning an `EmbeddedResource`):
```
kb.search (embedded resource) -> isError False | action allow | findings []
  client received raw card: True | raw key: True
```
The client received `AKIAIOSFODNN7EXAMPLE` and `4111111111111111` verbatim; action `allow`, no
findings, no taint.

Impact: full data-exfiltration and indirect-injection bypass of the MCP result controls, and no
taint means a later outbound call will not trip the lethal-trifecta rule.

Fix: enumerate every block type FastMCP can return. Extract text from `EmbeddedResource`
(`resource.text`) and any future text-bearing block and feed it through the same `scan_segment` +
`_semantic_injection` path as `TextContent`; apply redaction back into the block or withhold the
result. For block kinds whose content cannot be scanned (binary blobs), fail per `fail_mode` rather
than forwarding them.

---

### MEDIUM-1 MCP blocked-result audit excerpt stores the raw tool-result text
`bouncer/gateway/mcp_gateway.py:680-684` (`_inspect_result`)

The MCP path builds its own excerpt: `first = replaced.get(texts[0][1], "")`, where `replaced`
applies only findings whose `effective_action == REDACT` **and** that have a span. A value whose
action is `block` (e.g. `CREDIT_CARD`, which the policy blocks) is left raw, so the blocked result's
excerpt — written to `data/audit.jsonl` and returned by `/api/events` — contains the raw value. The
OpenAI and guard paths now route their excerpts through `audit_mask`/`_safe_excerpt`; the MCP path
does not.

Reproduction (`scripts/secreview/mcp_checks.py`, `crm.lookup_customer` returning a card):
```
crm.lookup_customer -> isError True | action block | findings ['pii.CREDIT_CARD']
  audit excerpt: crm.lookup_customer -> Customer C-1001: card 4111111111111111
```

Impact: breaks the documented guarantee "Only redacted excerpts and masked evidence are stored" for
the MCP route; raw PII/secrets land in the audit log and the dashboard event feed.

Fix: build the MCP result excerpt from `engine.audit_mask(ctx, first_text, "tool_result")` (as the
other routes now do), not from REDACT-span findings only.

---

### MEDIUM-2 Input content parts of a non-standard `type` are forwarded unscanned
`bouncer/messages.py:30-41` (`content_parts`)

`content_parts` extracts text only from parts whose `type` is exactly `"text"` or `"input_text"`.
A message whose content is a list with a part of any other type that still carries a `text` field
(e.g. `{"type":"output_text","text":"..."}`, or a part with a `text` key and no `type`) is skipped
by every control, yet the whole body is forwarded to the upstream as-is (`fwd = dict(body)`, only
scanned locations are rewritten). Secrets/PII in such a part reach the external model unredacted.

Reproduction (`scripts/secreview/checks.py` content-part test):
```
content-part type 'output_text' forwarded raw key to upstream: True
```

Impact: secrets/PII redaction-before-forwarding bypass (threat-model boundary 2). Severity depends on
the upstream honoring the part; many OpenAI-compatible servers concatenate any `text` field.

Fix: in `content_parts`, scan the `text` of every part that has a string `text` field regardless of
`type` (and treat an unknown non-text part conservatively), or reject unknown part types.

---

### MEDIUM-3 CSV audit export is formula-injection-prone
`bouncer/audit.py:164-191` (`to_csv`)

`to_csv` writes `session_id`, `excerpt`, `findings`, etc. with RFC-4180 quoting only; it does not
neutralize cells that begin with `=`, `+`, `-`, `@`, or tab/CR. `session_id` comes from the client
(`X-Bouncer-Session`) and `excerpt` is attacker-influenced content. When a bank SOC opens
`/api/export/audit.csv` in Excel/Sheets, such a cell is evaluated as a formula.

Reproduction (`scripts/secreview/checks.py` csv test), a message `=1+2 starts this message` and
session id `=SUM(1,1)`:
```
...,"ops-copilot/=SUM(1,1)",openai.chat,output,...,=1+2 starts this message,...
```
Both land as live-formula cells.

Fix: prefix any cell that starts with `= + - @` (or a control char) with a `'` or a space when
writing CSV.

---

### MEDIUM-4 Per-session budgets and the loop breaker are evaded by rotating `X-Bouncer-Session`
`bouncer/gateway/openai_proxy.py:38-48 / 173-176`, `bouncer/pipeline.py:255-325, 718-737`

The session id is taken verbatim from the client header `X-Bouncer-Session` (or derived from the
message content) with no binding to the principal. `budgets.sessions.max_usd`, `max_steps`, the
identical-call loop counter and the circuit breaker are all keyed on that id, so a client that sends a
fresh random session id per request never accumulates session spend, step count, or repeat-call
count. The only hard backstop is the team daily budget (`team_usd_per_day`).

Reproduction (`scripts/secreview/checks.py` session_growth): 300 requests with distinct session ids;
the loop breaker never fires and each session shows one step. (The unbounded-memory half of this was
fixed during the review — see FIXED-7.)

Impact: session-scoped limits are advisory; a runaway or abusive agent evades them by rotating the
header. Also lets one principal write taint onto another principal's session id (observed), which only
tightens, so it is not an escalation but is surprising.

Fix: derive the session id as `hash(principal.id + client-supplied id)` so a session cannot be shared
across principals, and treat the per-session limits as best-effort (document that team budgets are the
enforceable control), or bind session counters to the principal.

---

### LOW-1 Audit hash chain does not detect tail truncation
`bouncer/audit.py:61-76 (_resume), 194-228 (verify_file)`

The chain links each line to the previous one, so mid-file edits, deletes and reorders are detected.
But there is no persisted high-water mark (last seq/hash) outside the file itself: deleting the last N
lines leaves a valid chain, `verify_file` returns `ok: true`, and on restart `_resume` continues from
the truncated tail. An attacker who can write the file can drop the most recent (incriminating)
events undetectably.

Reproduction (deleting the last 2 of 4 lines): `verify_file` returns `{'ok': True, 'checked': 2}`.

Fix: anchor the head — persist `(max_seq, last_hash)` to a separate location (or emit it to the SIEM /
sign it), and have `verify-audit` take an expected tail length/seq to compare against.

---

### LOW-2 `judge.allow_external: false` host check is defeated by URL userinfo
`bouncer/policy/schema.py:334-341`

The local-only check parses the host with
`self.judge.url.split("://",1)[-1].split("/",1)[0].split(":",1)[0]`. For
`http://localhost:x@judge-host.example:8701` this yields `localhost` (the text before the first `:`),
so the policy passes validation, while `httpx` connects to `judge-host.example`. An insider with
config access can therefore point the judge off-box despite `allow_external: false`, which the schema
claims to enforce (threat-model boundary 5).

Reproduction (`scripts/secreview/checks.py` judge_url_userinfo): policy accepted; `httpx.URL(...).host
== "judge-host.example"`.

Fix: parse the host with `urllib.parse.urlsplit(url).hostname` and validate that, not a hand-rolled
split.

---

## Fixed during the review (reproduced, then verified fixed)

- **FIXED-1 Guard API wrote raw secrets/PII into the audit excerpt.** `/v1/guard/check` stored
  `clean` (and raw tool-call args) in `ctx.excerpt`. Now routed through `engine.audit_mask`
  (`bouncer/gateway/guard_api.py:78,88`, `bouncer/pipeline.py:442 audit_mask`). Verified: excerpt now
  `aws_key=[REDACTED:aws-access-key-id] card [REDACTED:CREDIT_CARD]`; no raw value in the file.
- **FIXED-2 `output_safety` finding evidence stored the full exfiltration URL** (query/fragment carry
  the smuggled data, e.g. a card number). Now masked via `_mask_query`
  (`bouncer/controls/output_safety.py:296,321,375`). Verified: `evidence: https://img.example.net/p.png?[masked]`.
- **FIXED-3 Tool-call arguments in the audit record held raw PII** (the `pii` control does not run on
  the `tool_call` direction, so a card/email in a `mail.send` body was logged raw). `inspect_tool_calls`
  now masks via `_masked_args` → `audit_mask`, which scans secrets+PII regardless of the policy's
  `directions` (`bouncer/pipeline.py:738`). Verified masked.
- **FIXED-4 Judge received raw secrets/PII** in `USER_REQUEST` and the goal-alignment
  `PROPOSED_ACTION`. Both now masked with `audit_mask` (`bouncer/pipeline.py:615,916`). Verified: judge
  state shows `[REDACTED:...]`.
- **FIXED-5 Model response fields other than `content`/`tool_calls` reached the client unscanned**
  (e.g. `reasoning_content` from reasoning models carrying a key). `finish_plain` now scans
  `content, reasoning_content, reasoning, refusal` and redacts them; the stream path drops
  `reasoning_content`/`reasoning` (`bouncer/gateway/openai_proxy.py:299-345,461-470`). Verified:
  `reasoning_content` redacted, action `redact`.
- **FIXED-6 Legacy `function_call` responses bypassed tool governance.** Now routed through
  `inspect_tool_calls` (non-stream) and flagged/blocked in streams; legacy `functions` request
  definitions are scanned as tool definitions (`bouncer/gateway/openai_proxy.py:313-321,492-504`,
  `bouncer/messages.py:103-106`). Verified: external `mail_send` via `function_call` → 403 block.
- **FIXED-7 Approval reuse.** (a) A tool-call approval was reusable repeatedly for its whole TTL and
  across sessions; `store.approved()` now consumes it (`status="used"`) and binds to
  `(principal_key, call_hash, session_id)` (`bouncer/store.py:213-228`). Verified: replays return 403.
  (b) Input-level approvals were keyed on only the first 300 chars of the last message
  (`call_hash("input", _excerpt(...))`), so a different tail auto-approved; the key is now
  `call_hash("input", request_text(body))` over the full request (`bouncer/pipeline.py:425`).
  Verified: altered content re-prompts for approval.
- **FIXED-8 Unbounded session memory.** `store.sessions` was a `defaultdict` keyed by attacker-chosen
  ids; now a bounded `OrderedDict` with `max_sessions=50000` LRU eviction (`bouncer/store.py:82-101`).
- **FIXED-9 Secrets in tool definitions / in historical tool-call arguments were forwarded raw to the
  upstream.** Both are now scanned/redacted (`bouncer/messages.py:93-106`). Verified: tool-def secret
  → 403; history tool-call secret → redacted, upstream clean.
- **FIXED (before this review) Admin API auth and self-approval.** `/api/*`, `/admin/*`, `/reports/*`
  now always require a bearer token (random per run unless set; `off` to disable), compared with
  `hmac.compare_digest` (`bouncer/gateway/app.py:130-140`, `bouncer/gateway/state.py:47-63`). Agent
  keys cannot decide approvals; `GET /v1/approvals/{id}` only reads the caller's own approval
  (`bouncer/gateway/openai_proxy.py:109-119`). Verified: no token → 401; agent key → 401; `?token=`
  honored; `/metrics` gated. Note for tests: `Settings(...)` built directly still defaults
  `admin_token=None` (open) — only `Settings.from_env()` enforces, so in-process tests are open by
  design.

---

## Checked and held up (safe to cite)

- **Proxy input excerpt** uses `_safe_excerpt` (masks every secret/PII span, withholds a segment when
  a value was found only in a normalized/decoded form). Verified no raw key/card in the audit file for
  the chat path.
- **Redaction before the upstream** for normal content: secrets redacted, and PII enforced for an
  external model even when the principal has clearance (`_enforce_pii_for_external_model`). Verified
  the simulated upstream never received the raw key/card for the standard content path.
- **Streaming holdback (`StreamGuard`)**: a secret/`data:` image URL split across chunks is still
  caught and redacted across the boundary (observed `[REDACTED:SIG-0002]` for a split image). Final
  SSE chunk carries the decision.
- **Signature feed**: a tampered feed, an unsigned feed (with `require_signature: true`), and a bad
  update are all rejected and the previous good version stays active. No private signing key is tracked
  in git. Public key length validated.
- **Policy hot reload**: an invalid policy keeps the last good version and keeps serving; `PUT
  /api/policy` writes to the fixed configured path only, atomically via `os.replace`, behind admin
  auth, with an `expected_version` conflict check.
- **Dashboard XSS**: `util.html`` escapes every interpolation unless wrapped in `Raw`; `excerptHtml`
  escapes then adds `[REDACTED]` marks; `charts.js`, `trace.js`, `policy.js` diff rendering all route
  attacker text through `esc()`/`html``; `safeUrl`/`extLink` emit links only for `http(s)`/`#/`. No
  attacker-controlled string reaches `innerHTML` unescaped in the paths reviewed (findings `evidence`,
  `message`, tool `arguments`, policy source, signature titles).
- **Catastrophic backtracking / large inputs**: 64/256/1024 KB user messages are blocked by
  `budgets.requests.max_input_tokens` before heavy scanning; each returned in < 0.2 s.
- **Audit chain** detects mid-file edit/delete/reorder (only tail truncation is missed — LOW-1).
- **Lethal trifecta / taint** over the chat and guard paths works; taint only tightens decisions.
- **Delegation (`X-Bouncer-On-Behalf-Of`)**: effective permissions are the intersection of caller and
  target (models/tools), the lower clearance and the stricter profile; unknown or un-allowed targets
  are denied. No privilege gain observed.

---

## Top open findings (priority order)

1. HIGH — MCP tool results in non-text blocks (EmbeddedResource) are not scanned → data leak +
   injection bypass. `bouncer/gateway/mcp_gateway.py:658-663`
2. MEDIUM — MCP blocked-result audit excerpt stores raw PII/secrets. `bouncer/gateway/mcp_gateway.py:680-684`
3. MEDIUM — input content parts of a non-standard `type` are forwarded to the model unscanned.
   `bouncer/messages.py:30-41`
4. MEDIUM — CSV audit export formula injection. `bouncer/audit.py:164-191`
5. MEDIUM — per-session budgets/loop breaker evaded by rotating `X-Bouncer-Session`.
   `bouncer/gateway/openai_proxy.py:38-48`
6. LOW — audit hash chain does not detect tail truncation. `bouncer/audit.py:194-228`
7. LOW — `judge.allow_external` host check defeated by URL userinfo. `bouncer/policy/schema.py:334-341`
