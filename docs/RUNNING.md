# Running Bouncer

How to install, run, test and measure Bouncer on your machine, natively with `uv` or with Docker.
Times below were measured on an Apple M4 Pro (14 cores, 48 GB), macOS 27.0.1, Python 3.12.11, uv 0.8.9,
Docker Desktop 29.8.1 with Compose v5.5.1.

## Prerequisites

| Need | For | Install |
|---|---|---|
| [uv](https://docs.astral.sh/uv/) | everything native | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Python 3.12 | everything native | installed by uv on first `uv sync` if missing (pinned in `.python-version`) |
| make | the shortcuts below | preinstalled on macOS and most Linux distributions |
| Ollama (optional) | live agent mode with a real local model, the `ollama-guard` judge | <https://ollama.com>, then `ollama pull qwen3:8b` / `ollama pull llama-guard3:1b` |
| Docker with Compose v2 (optional) | the container stack | Docker Desktop or Docker Engine |
| Apple Silicon (optional) | the Clef MLX judge (`make judge`) | the other judge backends run anywhere |

Nothing in `make test`, `make dev`, `make demo` or `make bench` needs a GPU, network access or model files.

## Quick start (native)

```
make setup      # uv sync (creates .venv with Python 3.12), copies .env.example to .env
make test       # offline test suite
make dev        # gateway :8700 + simulated model API :8702 + demo MCP server :8703 + feed server :8704
```

Then open the dashboard link that `make dev` prints (`http://localhost:8700/ui/?token=...`; the dashboard stores
the admin token and removes it from the address bar) and, in a second terminal:

```
make demo       # Bank Ops Copilot: scripted scenarios through the gateway, pass/fail table
```

`make dev` runs in the foreground; Ctrl-C stops all four services. It reads `.env`, generates a random admin token
when `BOUNCER_ADMIN_TOKEN` is empty, and, when no judge answers on :8701, starts the gateway with the deterministic
judge stand-in (`BOUNCER_JUDGE=fake`) and prints that it did. Start `make judge` first for the real judge.

## Commands

| Command | What it does | Needs |
|---|---|---|
| `make setup` | `uv sync`, creates `.env` from `.env.example` (dev agent keys), creates `data/` and `reports/tests/` | uv |
| `make models` | downloads the T1 classifier (ONNX, about 0.7 GB) and the Clef judge (MLX, about 4.9 GB) from Hugging Face, pulls `llama-guard3:1b` and `qwen3:8b` into Ollama | network, Ollama for the last two |
| `make test` | offline suite: YAML cases in `tests/cases/` through the real gateway in-process, plus unit tests. Fake T1 and fake judge, no network, no models | nothing else |
| `make dev` | gateway, simulated upstream, demo MCP server, feed server | nothing else |
| `make judge` | T2 judge service on :8701. Default backend Clef MLX (Apple Silicon); `JUDGE_BACKEND=ollama-guard make judge` elsewhere | `make models` |
| `make judge-fake` | judge service with the deterministic keyword backend (no model) | nothing else |
| `make demo` | scripted Bank Ops Copilot scenarios against the running stack (agent keys from `.env`) | `make dev` |
| `make test-live` | the YAML cases and AI-layer checks over real HTTP against the running stack (`tests/live/`) | `make dev`; `make judge` for the T2 checks |
| `make eval` | detection quality of T0 and T1 on `bank_ops` and `deepset_test`, `reports/eval_quick.md` | T1 model (`make models`) |
| `make eval-full` | the same plus the full pipeline with the T2 judge, `reports/eval_layers.md` | T1 model, `make judge` |
| `make bench` | gateway latency overhead and throughput, `reports/bench.md` | nothing else (uses the T1 model when present) |
| `make verify-audit` | checks the audit log hash chain (`AUDIT=path` to pick a file) | an audit log |
| `make sign-feed` | signs `signatures/feed.json`; creates a dev key in `data/` on first use | nothing else |
| `make lint` | ruff | nothing else |

### make test

`make test` runs `pytest -m "not live"`: every YAML case in `tests/cases/` goes through the real gateway
app in-process, with the simulated upstream mounted as a transport, the deterministic fake T1 classifier
and the scriptable fake judge, plus the unit tests. Measured: 1,097 tests in about 12 s wall time (pytest
reports 10 to 11 s) on the machine above; on two fresh clones the first run took 15 and 19 s wall time
(13 and 16 s pytest) while Python compiled the modules. The test count grows as cases are added. Reports:

- `reports/tests/summary.md` and `summary.json`: pass/fail per control, allow and block case counts,
- `reports/tests/junit.xml`: JUnit XML for CI,
- `reports/tests/report.html`: self-contained HTML report.

To add a case without writing Python, append an entry to a file in `tests/cases/` (format: copy an existing
entry; every key is used by at least one case) and rerun `make test`.

### make test-live

Runs `tests/live/` against a running stack. Tests skip with the reason when `BOUNCER_URL/healthz` does
not answer. Two parts:

- `test_live_cases.py` re-runs the YAML cases over HTTP. Cases that rely on test-only hooks of the
  offline runner (`policy_patch`, scripted `judge` answers, pinned `t1_scores`) are skipped, as are steps
  whose model routes to a real model (for example `qwen3:8b` on Ollama) when the case needs a scripted
  reply. Scripted replies are pushed to `MOCK_URL/mock/script`, so do not run a scripted demo at the same time.
- `test_live_models.py` sends texts that only the AI layers can judge (an English indirect injection in
  a tool result that no T0 rule matches, a Polish indirect injection, benign English and Polish business
  prompts, a benign vendor page) and a missed injection followed by an exfiltration tool call. The tests
  that need the judge skip when the judge is fake, disabled or unhealthy.

At the end the session prints per-layer latency (T0, T1, T2, upstream, gateway overhead), the highest T1
score, the judge call and the findings for every request.

Measured against the running stack with the real T1 and the Clef judge (`reports/tests/summary_live.md`,
2026-10-04 01:16): 358 passed, 75 skipped, 0 failed in 21 s. An earlier run of the five AI-layer checks alone
(session output, not saved in `reports/`) passed in 2.95 s: the English injection was escalated by T1 (score 1.0)
and blocked by the judge (T2 1,147 ms); the Polish injection and the benign Polish prompt went to the judge as
non-English text (675 ms and 661 ms) and were blocked and allowed respectively; the benign English prompt cost
9.4 ms of T1.

Settings: `BOUNCER_URL` (default `http://localhost:8700`), `MOCK_URL` (default `http://localhost:8702`),
`BOUNCER_ADMIN_TOKEN` (the gateway's admin token: the value in `.env`, or the one in the dashboard link that
`make dev` prints), agent keys from the environment or `.env`.

### make bench

Starts its own simulated upstream and gateway on :8706 and :8705 (no LLM, fake judge, real T1 when the
model files exist), measures client-observed latency direct vs through the gateway for seven scenarios,
the gateway's own per-layer timings from the audit log, throughput at 1, 8 and 32 concurrent clients,
and a comparison pass with T1 disabled. Full run measured at 84-86 s (124 s while the machine was busy),
`uv run python scripts/bench.py --quick` about 22 s. Results: `reports/bench.md`, `reports/bench.json`. Ports can be changed with
`--gateway-port` / `--mock-port`.

## Ports

All services bind to 127.0.0.1 (natively and, through the published ports, in Docker).

| Port | Service | Started by |
|---|---|---|
| 8700 | gateway: OpenAI-compatible proxy `/v1`, MCP gateway `/mcp`, guard API `/v1/guard/check`, dashboard `/ui/`, admin API `/api/*`, `/metrics`, `/healthz` | `make dev`, `make gateway`, compose `gateway` |
| 8701 | T2 judge (`POST /v1/decide`, `GET /health`) | `make judge`, compose profile `cpu-judge` |
| 8702 | simulated "commercial" model API (scripted replies, request log) | `make dev`, `make mock`, compose `mock` |
| 8703 | demo MCP server `demo-bank` (`/mcp`, `/health`, `/admin/poison`) | `make dev`, `make mcp`, compose `mcp` |
| 8704 | signature feed server (`/feed.json`, `/feed.json.sig`, `/feed.pub`) | `make dev`, `make feed`, compose `feed` |
| 8705, 8706 | `make bench` (its own gateway and mock) | `scripts/bench.py` |
| 6390 | Redis: shared store for several gateway replicas (`BOUNCER_STORE=redis://127.0.0.1:6390/0`) | compose profile `redis` |
| 11434 | Ollama (external, shared) | Ollama |

## Environment variables

Read from the environment; the gateway also loads `.env` from the repository root (values already set
in the environment win).

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `BOUNCER_KEY_OPS_COPILOT`, `BOUNCER_KEY_DEV_ASSISTANT`, `BOUNCER_KEY_INTERN_BOT`, `BOUNCER_KEY_PLAYGROUND` | dev keys in `.env.example` | gateway, demo, live tests | agent API keys; the policy names the variable per principal (`principals.<id>.key_env`) |
| `BOUNCER_POLICY` | `policy/bouncer.yaml` | gateway | policy file (hot reloaded) |
| `BOUNCER_HOST` / `BOUNCER_PORT` | `127.0.0.1` / `8700` | gateway | listen address |
| `BOUNCER_AUDIT_PATH` | `audit.path` from the policy (`data/audit.jsonl`) | gateway | audit log file |
| `BOUNCER_AUDIT_FSYNC` | off | gateway | `1` = fsync after every audit line |
| `BOUNCER_T1` | `auto` | gateway | `auto` (ONNX when `T1_MODEL_PATH/model.onnx` exists, else the fake classifier), `onnx`, `fake`, `off` |
| `T1_MODEL_PATH` | `models/deberta-pi-v2/onnx` | gateway | T1 model directory |
| `T1_CONCURRENCY` | `3` | gateway | T1 inferences that may run at the same time (one shared ONNX session) |
| `BOUNCER_JUDGE` | unset (policy `judge.backend`) | gateway | force a judge backend: `fake` (in-process, no model), `none`, or a remote backend name |
| `BOUNCER_ADMIN_TOKEN` | empty: a random token per run (logged by the gateway; `make dev` prints a dashboard link with it) | gateway, `make dev`, live tests | `/api/*`, `/admin/*` and `/reports/*` need `Authorization: Bearer <token>`; agent keys are not accepted there. `off` disables the check (unsafe on a host that agents share) |
| `BOUNCER_WATCH` | `1` | gateway | `0` disables policy hot reload and feed refresh |
| `BOUNCER_STORE` | `memory` | gateway | where budgets, sessions, approvals and MCP pins live: `memory` (this process only) or `redis://host:port/db` (shared by several replicas; the gateway refuses to start when Redis is unreachable) |
| `BOUNCER_STORE_PREFIX` | `bouncer:` | gateway | key prefix in Redis; separate deployments on one Redis need different prefixes |
| `BOUNCER_LOG_LEVEL` | `INFO` | gateway | Python log level |
| `BOUNCER_MCP_UPSTREAM` | `http://127.0.0.1:8703/mcp` | gateway | MCP server behind the `/mcp` gateway |
| `BOUNCER_MCP_SERVER`, `BOUNCER_MCP_RECHECK_SECONDS` | unset, `0` | gateway | MCP server name override; tool definitions are re-read from the server before a call when the last check is older than this (0 = before every call) |
| `JUDGE_BACKEND` | `clef-mlx` | judge | `clef-mlx`, `ollama-guard`, `fake` |
| `JUDGE_HOST` / `JUDGE_PORT` | `127.0.0.1` / `8701` | judge | listen address |
| `CLEF_MLX_PATH` | `models/clef-flash-mlx-4bit` | judge | Clef model directory |
| `JUDGE_MAX_TOKENS`, `JUDGE_MAX_QUEUE` | `1536`, `16` | judge | prompt token cap per decision for Clef (longer untrusted content is cut in the middle), queued requests before 503 |
| `OLLAMA_URL`, `OLLAMA_GUARD_MODEL` | `http://localhost:11434`, `llama-guard3:1b` | judge (`ollama-guard`) | Ollama endpoint and model |
| `MOCK_PORT` | `8702` | simulated upstream | listen port |
| `MCP_HOST`, `MCP_PORT` | `127.0.0.1`, `8703` | demo MCP server | listen address |
| `DEMO_MCP_POISON`, `DEMO_MCP_FLAG` | `0`, `data/mcp_poison.flag` | demo MCP server | start with the poisoned tool description / flag file that toggles it |
| `BOUNCER_URL`, `MOCK_URL` | `http://localhost:8700` (`/v1` for the demo agent), `http://localhost:8702` | demo agent, live tests | where the running stack is |
| `BOUNCER_MCP_URL`, `DEMO_MCP_ADMIN_URL` | the gateway's `/mcp`, `http://127.0.0.1:8703` | demo agent (`s8`) | MCP gateway URL and the demo MCP server's poison toggle |
| `LIVE_MOCKED_UPSTREAMS`, `LIVE_TIMEOUT_S` | detected from the policy, `30` | live tests | upstream names that point at the mock; per-request timeout |
| `BENCH_GATEWAY_PORT`, `BENCH_MOCK_PORT` | `8705`, `8706` | `scripts/bench.py` | benchmark ports |

## Docker

One image (`Dockerfile`, Python 3.12 slim, dependencies from `uv.lock` with `uv sync --frozen`) serves every
service; `docker-compose.yml` (project name `bouncer`) wires them together.

```
docker compose up -d --build          # gateway, mock, mcp, feed; dashboard at http://localhost:8700/ui/
docker compose ps                     # all four should report (healthy)
docker compose run --rm tests         # offline suite in a container with no network; reports in ./reports/tests
docker compose logs -f gateway
docker compose down                   # add -v to delete the audit log volume
```

Measured: first `docker compose build` 82 s including base image download, runtime image 729 MB;
`docker compose run --rm tests` ran 1,061 tests (the count at the time) in 9.3 s (pytest time) in a container
with `network_mode: none`.

How the container stack differs from `make dev`:

- **Policy.** `./policy` is mounted read-only. `policy/bouncer.yaml` refers to its upstreams and judge by
  `localhost` URLs, so the gateway's entrypoint (`docker/gateway_entrypoint.py`) writes a container copy
  to `/tmp/bouncer-policy/bouncer.yaml` with those URLs rewritten (simulated upstream -> `http://mock:8702`,
  Ollama -> `http://host.docker.internal:11434`, judge -> `http://judge:8701`), compares the source with the
  copy twice a second and rewrites it when you edit `./policy/bouncer.yaml` on the host. Hot reload works
  as natively: measured 0.5 s from saving the file to the new version being active, and an invalid file is
  rejected with its line number while the last good version stays active. The dashboard shows the copy's
  path. Rewrites are configurable with `BOUNCER_URL_REWRITES` (comma-separated `FROM=TO`).
- **T1.** `./models` is mounted read-only. With `models/deberta-pi-v2/onnx/model.onnx` present (`make models`)
  the gateway uses the real classifier, otherwise the fake one (`BOUNCER_DOCKER_T1=onnx|fake|off` forces it).
- **Judge.** By default the gateway in Docker uses the deterministic judge stand-in (`BOUNCER_DOCKER_JUDGE=fake`),
  so the stack works on any machine without a model; the dashboard shows the backend as `fake`. For a real judge,
  clear that variable and pick one:
  - `BOUNCER_DOCKER_JUDGE= docker compose --profile cpu-judge up -d`: judge container with the `ollama-guard`
    backend, which calls Ollama on the host (`ollama pull llama-guard3:1b` first);
  - on a Mac with `make judge` running natively:
    `BOUNCER_DOCKER_JUDGE= BOUNCER_DOCKER_JUDGE_URL=http://host.docker.internal:8701 docker compose up -d`
    (Docker Desktop forwards `host.docker.internal` to services bound to the host's 127.0.0.1; checked from
    inside the gateway container).
  Without a reachable judge, escalations fail closed (see Troubleshooting).
- **Audit log** lives in the named volume `bouncer-data` (`/app/data`). Verify it with
  `docker compose exec gateway python scripts/verify_audit.py data/audit.jsonl`, or export it from the dashboard.
- **Keys** come from `./.env` when present (`make setup`), otherwise the dev keys from `.env.example`.
- **Admin token**: `BOUNCER_ADMIN_TOKEN` from `./.env` or the shell; when it is empty the gateway generates one at
  start and logs it with a dashboard link (`docker compose logs gateway | grep BOUNCER_ADMIN_TOKEN`).
- **Ports** bind to 127.0.0.1. Change the host side with `BOUNCER_HOST_PORT`, `MOCK_HOST_PORT`,
  `MCP_HOST_PORT`, `FEED_HOST_PORT`, `JUDGE_HOST_PORT`, `REDIS_HOST_PORT`.
- **Redis** (`--profile redis`, :6390) is the shared store for several gateway replicas. The gateway uses it
  only when `BOUNCER_STORE` points at it (see [Several replicas](#several-replicas)); the compose `gateway`
  service keeps the in-memory store.
- The Clef MLX judge does not run in Linux containers (MLX needs Apple Silicon); the image skips `mlx`,
  `mlx-lm` and `transformers` through the platform markers in `pyproject.toml`.
- Containers run as an unprivileged user (uid 10001), except the throwaway `tests` container, which runs
  as root only so it can write the report into the bind-mounted `./reports/tests` on Linux hosts.

Not verified: the `cpu-judge` profile end to end (it would load `llama-guard3:1b` into the shared Ollama),
the compose `gateway` service with `BOUNCER_STORE` set, and Docker Engine on Linux (`host.docker.internal` is mapped with `host-gateway`;
on Linux, Ollama must listen on an address the containers can reach, for example `OLLAMA_HOST=0.0.0.0`).

## Several replicas

By default each gateway keeps budgets, sessions (taint, steps, loop history, circuit breaker), approvals and
MCP pins in its own memory. With `BOUNCER_STORE=redis://...` they live in Redis and every replica sees the
same values: a team's daily spend counts requests from all replicas, an approval granted through one replica
lets the agent's call through on another, exactly once. The scan caches stay local to each replica, and each
replica writes its own audit log.

Two replicas on one host, run from the repository root (the simulated upstream on :8702 must be running,
for example from `make dev`; ports 8705 and 8706 are also the `make bench` ports, so do not run both at once):

```
docker compose --profile redis up -d redis

BOUNCER_PORT=8705 BOUNCER_STORE=redis://127.0.0.1:6390/0 BOUNCER_AUDIT_PATH=/tmp/bouncer-r1/audit.jsonl \
  BOUNCER_WATCH=0 BOUNCER_JUDGE=fake BOUNCER_ADMIN_TOKEN=adm_test uv run python -m bouncer.gateway.app &
BOUNCER_PORT=8706 BOUNCER_STORE=redis://127.0.0.1:6390/0 BOUNCER_AUDIT_PATH=/tmp/bouncer-r2/audit.jsonl \
  BOUNCER_WATCH=0 BOUNCER_JUDGE=fake BOUNCER_ADMIN_TOKEN=adm_test uv run python -m bouncer.gateway.app &

# a request through replica 1 ...
curl -s localhost:8705/v1/chat/completions -H "Authorization: Bearer $BOUNCER_KEY_OPS_COPILOT" \
  -H "X-Bouncer-Session: r-1" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"What are the branch hours?"}]}'
# ... is counted in the operations budget on replica 2
curl -s localhost:8706/api/budgets -H "Authorization: Bearer adm_test"

# a transfer above the limit needs approval on replica 1, is approved on replica 2,
# passes once on replica 2 and needs a new approval on replica 1
cat > /tmp/transfer.json <<'JSON'
{"tool_call": {"name": "payments.create_transfer", "arguments": {"from_account": "A",
 "to_iban": "PL61109010140000071219812874", "amount": 5000, "currency": "PLN", "title": "invoice 17"}},
 "user_request": "pay invoice 17, 5000 PLN"}
JSON
check() {  # $1 = gateway port
  curl -s localhost:$1/v1/guard/check -H "Authorization: Bearer $BOUNCER_KEY_OPS_COPILOT" \
    -H "Content-Type: application/json" -H "X-Bouncer-Session: r-2" -d @/tmp/transfer.json; echo
}
check 8705    # "action":"require_approval", "approval_id":"apr_..."
curl -s localhost:8706/api/approvals/apr_... -H "Authorization: Bearer adm_test" \
  -H "Content-Type: application/json" -d '{"decision":"approve"}'
check 8706    # "action":"log", "allowed":true: the approval is consumed
check 8705    # "action":"require_approval" again
curl -s localhost:8705/v1/approvals/apr_... -H "Authorization: Bearer $BOUNCER_KEY_OPS_COPILOT"   # "status":"used"
```

What was checked this way (both replicas with the policy from this repository): after one chat request
through :8705, `/api/budgets` on :8706 showed the operations team with `requests: 1`, `spent_usd: 0.000015`
and `tokens_last_minute: 44`; an approval created on :8705 and approved on :8706 let the same tool call through
once on :8706, `GET /v1/approvals/<id>` on :8705 returned `"status": "used"`, the same call on :8705 needed
a new approval, and deciding the approval again on :8705 returned 409. With `BOUNCER_STORE` pointing at a
Redis that does not answer, the gateway logs `Redis is not reachable` and exits with code 2.
`tests/unit/core/test_store_redis.py` covers the same behaviour offline with `fakeredis` (two stores on one
fake server, and two gateway apps sharing it).

Keep the policy files of all replicas identical (each replica hot-reloads its own copy). A load balancer in
front of the replicas and Redis Sentinel or Cluster were not tested.

## Troubleshooting

**Port already in use.** `lsof -nP -iTCP:8700 -sTCP:LISTEN` shows the owner. Natively, start single services
on other ports (`BOUNCER_PORT=8710 make gateway`, `MOCK_PORT=8712 make mock`; point the policy's
`upstreams.commercial-mock.base_url` at the new mock port). In Docker, set `BOUNCER_HOST_PORT` and friends.
`make bench` refuses to start when 8705 or 8706 is taken; pass `--gateway-port` / `--mock-port`.

**Model files missing.** With `BOUNCER_T1=auto` (the default) and no `models/deberta-pi-v2/onnx/model.onnx`,
the gateway silently uses the deterministic fake T1 classifier: everything runs, but T1 scores come from
keyword rules. `BOUNCER_T1=onnx` with missing files does not fall back: the first T1 call fails, and every request
that reaches T1 follows `defaults.fail_mode` (with `closed`, the default, it is blocked with
`prompt_injection.control_error`, and the message names the missing file).
Fix: `make models`. A judge that cannot load its model says so in `GET :8701/health`.

**Judge down or slow.** Requests that escalate to T2 (T1 grey zone, non-English text, side-effect tool calls)
follow `defaults.fail_mode` in the policy: `closed` (default) blocks them with a finding such as
`prompt_injection.judge_unavailable` or `tool_governance.judge_unavailable`; `open` lets them through and
logs the finding. `GET /api/policy` shows the judge's health (`judge.healthy`, `judge.health`). Start a judge (`make judge`,
`JUDGE_BACKEND=ollama-guard make judge`, `make judge-fake`), or run the gateway with `BOUNCER_JUDGE=fake`
(`make dev` does that by itself when no judge answers at start; a judge that goes down later is not replaced).
With the real T1, non-English prompts and many prompts that contain configuration or secrets reach the
judge, so a stack without a judge blocks noticeably more: in a measured `make test-live` run against the
Docker stack without a judge, 64 of 353 executed tests failed for this reason alone.

**`make test-live` skips everything.** The gateway is not reachable at `BOUNCER_URL`; start `make dev` (or
the compose stack) or point `BOUNCER_URL` / `MOCK_URL` at it. Export the gateway's admin token as
`BOUNCER_ADMIN_TOKEN` for the tests (or set it in `.env` before `make dev`).

**Policy change has no effect.** Check the dashboard (Policy, version history) or `GET /api/policy`: a rejected
file shows the error and line, and the previous version stays active. `BOUNCER_WATCH=0` turns hot reload off;
`POST /admin/policy/reload` reloads on demand.

**Wrong Python or missing packages.** Use `uv run ...` (or the make targets), which use `.venv` with Python 3.12.
`make setup` recreates it from `uv.lock`.
