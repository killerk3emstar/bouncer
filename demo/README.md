# Bank Ops Copilot demo

A small, deterministic demo for Bouncer: an agent that looks up customers, searches and writes to an
internal knowledge base, reads vendor pages, sends e-mail, creates transfers and (for the developer
assistant) asks to run Python, which is never executed, with every
model call, tool call and tool result flowing through the Bouncer gateway. All data is fake
and all side effects are simulated.

## Files

| File | What |
|---|---|
| `data.py` | 50 synthetic customers (Faker, seed 7) and 16 internal KB articles. Identifiers pass their checksums (PESEL, IBAN mod-97, Luhn) so Bouncer's validated PII detectors fire. |
| `tools.py` | Tool implementations and OpenAI tool JSON schemas. No network, no side effects. |
| `naming.py` | Policy name (`crm.lookup_customer`) <-> OpenAI wire name (`crm__lookup_customer`). No deps; the gateway can import it. |
| `web/vendor.example/` | Static pages served by `web.fetch` (offline). Some carry indirect prompt injections. |
| `scenarios/*.yaml` | 12 scripted demo runs (scenarios 1-8, with variants 3b-3e). |
| `scenario.py` | Loader and schema validation for the scenario files. |
| `agent.py` | The Bank Ops Copilot CLI (OpenAI SDK -> Bouncer). Scripted and live modes. |
| `mock_upstream.py` | Simulated OpenAI upstream. Scripted replies + request log. |
| `mcp_server.py` | The same tools as an MCP server (demo-bank, :8703) with a tool-poisoning toggle. |

## Tool names on the wire

The policy (`policy/bouncer.yaml`) names tools with dots: `crm.lookup_customer`.
OpenAI function names must match `^[a-zA-Z0-9_-]{1,64}$`, so on the OpenAI wire the dots
become `__`:

```
wire name   = policy name with "." replaced by "__"   ->  crm__lookup_customer
policy name = wire name with "__" replaced by "."     ->  crm.lookup_customer
```

`demo/naming.py` has `to_wire_name` / `to_policy_name` (both idempotent). The gateway must
map the wire names it receives in `tools` and `tool_calls` back to policy names with the same
rule before applying `tool_governance`. MCP allows dots, so `mcp_server.py` keeps the dotted
names unchanged.

## Running the demo

Prerequisites: the gateway on :8700 and the mock upstream on :8702 (`make dev`), and the agent
keys in `.env` (`make setup` copies `.env.example`; the agent reads `.env` itself).

```
# one scripted scenario (deterministic, no real LLM)
uv run python -m demo.agent --mode scripted --scenario s3

# all scripted scenarios with a pass/fail summary table
uv run python -m demo.agent --mode scripted --all

# a real model through Bouncer (needs Ollama with a tool-capable model)
uv run python -m demo.agent --mode live --model qwen3:8b "Look up customer C-10007 and summarize their account"

# wait for a human approval in the dashboard, then retry the blocked call
uv run python -m demo.agent --mode scripted --scenario s3 --wait-approval
```

Environment variables (see `.env.example`): `BOUNCER_URL` (default `http://localhost:8700/v1`),
`MOCK_URL` (default `http://localhost:8702`), and one key per principal
(`BOUNCER_KEY_OPS_COPILOT`, `BOUNCER_KEY_DEV_ASSISTANT`, `BOUNCER_KEY_INTERN_BOT`,
`BOUNCER_KEY_PLAYGROUND`). The agent sends `X-Bouncer-Session: <uuid>` on every request and
reads `X-Bouncer-Action` / `X-Bouncer-Trace-Id` / `X-Bouncer-Policy-Version` from each response.

A Bouncer block arrives as HTTP 403 (or 429 for budgets/limits) with an OpenAI-style error body:

```json
{"error": {"type": "bouncer_blocked", "code": "tool_governance.lethal_trifecta",
           "message": "...", "trace_id": "tr_...", "approval_id": "apr_..."}}
```

The agent prints the message and stops; with `--wait-approval` it polls
`GET {gateway}/v1/approvals/{id}` with its own agent key until `{"status": "approved"}` and retries the
same call. The agent can only read the status of its own request; a human decides it in the dashboard.

## Mock upstream contract (scripted mode)

The agent drives the mock upstream (`demo/mock_upstream.py`):

- `POST /mock/reset` - clear the queue and the request log.
- `POST /mock/script` body `{"responses": [...], "replace": false}` - append scripted replies
  to a FIFO queue consumed by subsequent `/v1/chat/completions` calls.
- `GET /mock/requests?limit=N` - returns `{"count": <requests recorded>, "requests": [the last N]}` (the
  raw request bodies, used by tests and the scenario runner to prove a secret never reached the model).

Each scripted response item is one of:

```yaml
{content: "final answer text"}                                  # finish_reason stop
{tool_calls: [{name: "crm__lookup_customer", arguments: {query: "C-10007"}}]}  # finish_reason tool_calls
```

Optional per item: `usage: {prompt_tokens, completion_tokens}` (reported verbatim),
`delay_ms`, `error: {status, message}`, `chunk_size` (streaming). Tool-call `name` is the wire
name; `arguments` may be an object or a JSON string.

## Scenario files

`scenarios/*.yaml`, one per demo scenario. `kind: openai` (default) scenarios have
`principal`, `model`, `tools`, `user` and `responses`, plus an `expect` block the runner checks
(`outcome`, `code`, `upstream_must_not_contain`, `answer_must_not_contain`, `outbox_must_be_empty`,
per-step `action`/`findings`). `kind: mcp` (s8) has `mcp_steps` instead and is run against the
MCP gateway, not as an OpenAI chat. See `scenario.py` for the full schema.

The `expect` blocks describe the behaviour of the shipped `balanced` policy. `s7` documents the
hot-reload case: with the default policy the customer e-mail is redacted; after changing
`controls.pii.entities.EMAIL` to `block` the same request is blocked without a restart.

## MCP server and the rug-pull toggle

```
uv run python -m demo.mcp_server          # demo-bank, streamable HTTP on 127.0.0.1:8703/mcp
```

The server exposes the seven demo tools over MCP with their dotted names. A toggle swaps the
description of `kb.search` for a poisoned one (an `<IMPORTANT>` block instructing the model to
read `~/.ssh/id_rsa` and smuggle it through a parameter, in the style of the Invariant Labs
tool-poisoning write-up, April 2025). The description is rewritten in `on_list_tools`
middleware, so the poison appears and disappears without restarting the server, which is what
the gateway's definition pinning (`supply_chain.mcp.pin_tool_definitions`) detects as a rug pull.

Toggle three ways:

- env `DEMO_MCP_POISON=1` at startup;
- file flag `data/mcp_poison.flag` (path in `DEMO_MCP_FLAG`); write `1`/`0`;
- HTTP: `POST /admin/poison {"poison": true}`, read with `GET /admin/poison`.

`GET /health` returns `{"status": "ok", "server": "demo-bank", "poison": <bool>}`.

## Tests

`tests/unit/demo/` runs offline with no models and no network:

```
uv run pytest tests/unit/demo -q
```

Covers the tools, data checksums and determinism, `web.fetch` path mapping and traversal
rejection, the scenario files (parse, reference only known tools/principals/models, tools are a
subset of the principal's grants), and the MCP server (lists all tools in-process, poison
toggle swaps only `kb.search`).
