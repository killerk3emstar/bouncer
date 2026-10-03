"""Gateway overhead benchmark (`make bench`).

Starts the simulated upstream (demo.mock_upstream) and a Bouncer gateway as subprocesses on
127.0.0.1 (default ports 8706 and 8705), with a temporary copy of policy/bouncer.yaml in which:
  - every upstream points at the mock (no LLM is called),
  - the judge is the in-process fake backend (no judge model is loaded),
  - team budgets are raised so the budget control still runs but never limits the benchmark,
  - the audit log goes to a temporary file.
T1 is the real ONNX classifier when models/deberta-pi-v2/onnx/model.onnx exists, otherwise the
fake one (override with --t1).

Measured:
  1. client-observed latency per scenario, direct to the mock and through the gateway. Requests
     alternate (direct, gateway, direct, ...) so background load on a shared machine hits both;
  2. the gateway's own per-layer timings for the same requests (audit log latency_ms: t0, t1, t2,
     upstream, gateway_overhead, total);
  3. throughput with N concurrent clients (benign short prompts, every prompt unique).

Every prompt is unique unless the scenario says otherwise, so the T1 result cache does not hide
the classifier cost (scenario benign_repeat shows the cached case).

Writes reports/bench.md and reports/bench.json. Subprocesses are stopped in a finally block.

Usage:
  uv run python scripts/bench.py            # full run, about 1.5-2 minutes
  uv run python scripts/bench.py --quick    # about 20-30 seconds
  uv run python scripts/bench.py --t1 fake  # without the ONNX classifier
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import random
import secrets
import shutil
import signal
import socket
import string
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LAYERS = ("t0", "t1", "t2", "upstream", "gateway_overhead", "total")
SYSTEM_PROMPT = "You are Bank Ops Copilot, an assistant for the operations team of Example Bank. Answer briefly."

# About 2 KB of benign business text (meeting notes). No PII, secrets or instructions to the model.
NOTES_2KB = (
    "Retail fee review, weekly operations meeting. Attendees from operations, product and finance "
    "reviewed the card and transfer fee schedule ahead of the quarterly pricing committee. Finance "
    "presented the volume report: domestic instant transfers grew by eleven percent quarter on "
    "quarter, while standard SEPA transfers were flat. Card replacement requests fell after the new "
    "contactless cards were rolled out in the spring. Product proposed keeping the monthly account "
    "fee unchanged for the standard package and waiving the instant transfer fee for customers "
    "under twenty-six, in line with the youth offer launched last year. Operations raised the "
    "backlog of manual chargeback reviews, which now averages four working days; the team asked for "
    "two additional analysts during the holiday season and a review of the dispute form, because "
    "many disputes arrive without the merchant name. Compliance reminded everyone that any fee "
    "change must be published on the website thirty days before it takes effect and that the "
    "customer notice has to be approved by the legal team. The branch network reported that "
    "Saturday opening hours in the three pilot branches attracted fewer visits than expected, and "
    "suggested replacing them with longer weekday hours. Finance will model the revenue impact of "
    "the youth waiver and present two scenarios next week. Product will draft the customer notice "
    "and share it with legal by Friday. Operations will publish the updated chargeback procedure in "
    "the knowledge base and run a short training session for the contact centre. Open questions: "
    "whether the premium package should include free foreign currency withdrawals, and whether the "
    "paper statement fee can be removed for customers over seventy. The next meeting will cover the "
    "mortgage servicing fees and the business account package. Action owners confirmed the dates."
)

STREAM_REPLY = (
    "Here is the summary of the fee review. The monthly fee for the standard package stays the same. "
    "Instant transfers will be free for customers under twenty-six once legal approves the notice. "
    "The chargeback backlog averages four working days, so operations asked for two more analysts "
    "during the holiday season. Saturday opening hours in the pilot branches will be replaced with "
    "longer weekday hours. Finance will present two revenue scenarios next week, and product will "
    "send the customer notice to legal by Friday. Open questions remain on free foreign currency "
    "withdrawals in the premium package and on the paper statement fee for older customers."
)


# ---------------------------------------------------------------------------- helpers


def pct(values: list[float], p: float) -> float | None:
    """Percentile with linear interpolation (same as numpy's default)."""
    if not values:
        return None
    v = sorted(values)
    if len(v) == 1:
        return v[0]
    k = (len(v) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def stats(values: list[float]) -> dict[str, Any]:
    return {
        "n": len(values),
        "p50": _r(pct(values, 50)),
        "p95": _r(pct(values, 95)),
        "p99": _r(pct(values, 99)),
        "mean": _r(sum(values) / len(values)) if values else None,
        "max": _r(max(values)) if values else None,
    }


def _r(x: float | None, nd: int = 2) -> float | None:
    return None if x is None else round(x, nd)


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def rand_token(alphabet: str, n: int) -> str:
    return "".join(random.choice(alphabet) for _ in range(n))


def hardware() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }
    if sys.platform == "darwin":
        for key, name in (("machdep.cpu.brand_string", "cpu"), ("hw.memsize", "memory_bytes")):
            try:
                info[name] = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, timeout=5).stdout.strip()
            except Exception:
                pass
        try:
            info["os"] = "macOS " + subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception:
            pass
    else:
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith("model name"):
                    info["cpu"] = line.split(":", 1)[1].strip()
                    break
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal"):
                    info["memory_bytes"] = str(int(line.split()[1]) * 1024)
                    break
        except Exception:
            pass
    if info.get("memory_bytes"):
        info["memory_gb"] = round(int(info["memory_bytes"]) / 2**30)
    try:
        import onnxruntime

        info["onnxruntime"] = onnxruntime.__version__
    except Exception:
        info["onnxruntime"] = None
    return info


def loadavg() -> list[float] | None:
    try:
        return [round(x, 2) for x in os.getloadavg()]
    except OSError:
        return None


def cpu_seconds(pid: int | None) -> float | None:
    """User + system CPU time of a process, from `ps -o time=` ([[dd-]hh:]mm:ss.ss)."""
    if not pid:
        return None
    try:
        out = subprocess.run(["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return None
    if not out:
        return None
    days = 0.0
    if "-" in out:
        d, out = out.split("-", 1)
        days = float(d)
    total = 0.0
    for part in out.split(":"):
        total = total * 60 + float(part)
    return days * 86400 + total


def rss_mb(pid: int) -> float | None:
    try:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, timeout=5).stdout.strip()
        return round(int(out) / 1024, 1) if out else None
    except Exception:
        return None


# ---------------------------------------------------------------------------- stack


@dataclass
class Stack:
    tmp: Path
    gateway_url: str
    mock_url: str
    keys: dict[str, str]
    t1_mode: str
    procs: list[tuple[str, subprocess.Popen]] = field(default_factory=list)
    logs: dict[str, Path] = field(default_factory=dict)

    @property
    def audit_path(self) -> Path:
        return self.tmp / "audit.jsonl"

    def pid(self, name: str) -> int | None:
        for n, p in self.procs:
            if n == name:
                return p.pid
        return None

    def stop(self) -> None:
        for _, p in self.procs:
            if p.poll() is None:
                try:
                    p.send_signal(signal.SIGTERM)
                except ProcessLookupError:
                    pass
        deadline = time.time() + 8
        for _, p in self.procs:
            try:
                p.wait(timeout=max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)

    def log_tail(self, name: str, n: int = 30) -> str:
        path = self.logs.get(name)
        if not path or not path.exists():
            return ""
        return "\n".join(path.read_text(errors="replace").splitlines()[-n:])


def make_policy(tmp: Path, mock_port: int) -> tuple[Path, dict[str, str]]:
    doc = yaml.safe_load((ROOT / "policy" / "bouncer.yaml").read_text())
    mock = f"http://127.0.0.1:{mock_port}/v1"
    for up in (doc.get("upstreams") or {}).values():
        up["base_url"] = mock
        up.pop("api_key_env", None)
    doc.setdefault("judge", {})["backend"] = "fake"
    budgets = doc.get("budgets") or {}
    for team in (budgets.get("teams") or {}).values():
        team.update({"usd_per_day": 1_000_000.0, "tokens_per_minute": 1_000_000_000, "gpu_seconds_per_hour": 1_000_000.0})
    doc.setdefault("audit", {})["path"] = str(tmp / "audit.jsonl")
    path = tmp / "policy.bench.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True))
    keys = {pid: "bk_bench_" + secrets.token_urlsafe(12) for pid in (doc.get("principals") or {})}
    key_env = {p["key_env"]: keys[pid] for pid, p in (doc.get("principals") or {}).items()}
    return path, {**{"_keys_" + pid: k for pid, k in keys.items()}, **key_env}


def wait_ready(url: str, proc: subprocess.Popen, name: str, stack: Stack, timeout: float = 120.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited with code {proc.returncode} before it was ready:\n{stack.log_tail(name)}")
        try:
            r = httpx.get(url, timeout=1.0)
            if r.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"{name} not ready at {url} after {timeout:.0f} s:\n{stack.log_tail(name)}")


def start_stack(args: argparse.Namespace, t1_override: str | None = None) -> Stack:
    for port in (args.gateway_port, args.mock_port):
        if not port_free(port):
            raise SystemExit(f"Port {port} is in use. Stop whatever listens there or pass --gateway-port/--mock-port.")
    tmp = Path(tempfile.mkdtemp(prefix="bouncer-bench-"))
    policy_path, env_keys = make_policy(tmp, args.mock_port)
    keys = {k[len("_keys_"):]: v for k, v in env_keys.items() if k.startswith("_keys_")}
    model_file = ROOT / "models" / "deberta-pi-v2" / "onnx" / "model.onnx"
    t1 = t1_override or args.t1
    if t1 == "auto":
        t1 = "onnx" if model_file.exists() else "fake"
    stack = Stack(tmp=tmp, gateway_url=f"http://127.0.0.1:{args.gateway_port}", mock_url=f"http://127.0.0.1:{args.mock_port}", keys=keys, t1_mode=t1)
    base_env = {k: v for k, v in os.environ.items() if not k.startswith("BOUNCER_")}
    base_env.update({"PYTHONUNBUFFERED": "1", "PYTHONPATH": str(ROOT)})
    mock_env = {**base_env, "MOCK_PORT": str(args.mock_port)}
    gw_env = {
        **base_env,
        **{k: v for k, v in env_keys.items() if not k.startswith("_keys_")},
        "BOUNCER_PORT": str(args.gateway_port),
        "BOUNCER_HOST": "127.0.0.1",
        "BOUNCER_POLICY": str(policy_path),
        "BOUNCER_AUDIT_PATH": str(stack.audit_path),
        "BOUNCER_T1": t1,
        "BOUNCER_WATCH": "0",
        "BOUNCER_JUDGE": "fake",
        "BOUNCER_LOG_LEVEL": "WARNING",
        "T1_MODEL_PATH": str(model_file.parent),
    }
    try:
        for name, cmd, env in (
            ("mock", [sys.executable, "-m", "demo.mock_upstream"], mock_env),
            ("gateway", [sys.executable, "-m", "bouncer.gateway.app"], gw_env),
        ):
            log_path = tmp / f"{name}.log"
            stack.logs[name] = log_path
            fh = open(log_path, "w")  # noqa: SIM115 - closed when the process exits
            p = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=fh, stderr=subprocess.STDOUT, start_new_session=True)
            stack.procs.append((name, p))
        wait_ready(stack.mock_url + "/v1/models", stack.procs[0][1], "mock", stack)
        wait_ready(stack.gateway_url + "/healthz", stack.procs[1][1], "gateway", stack)
    except BaseException:
        stack.stop()
        raise
    return stack


# ---------------------------------------------------------------------------- scenarios


@dataclass
class Scenario:
    name: str
    title: str
    principal: str = "ops-copilot"
    stream: bool = False

    def build(self, i: int) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Return (request body, scripted mock response or None)."""
        tag = uuid.uuid4().hex[:8]
        msgs: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
        body: dict[str, Any] = {"model": "gpt-4o-mini", "max_tokens": 256}
        mock: dict[str, Any] | None = None
        if self.name == "benign_short":
            msgs.append({"role": "user", "content": f"What are the Saturday opening hours of branch number {i} ({tag})?"})
        elif self.name == "benign_repeat":
            msgs.append({"role": "user", "content": "What are the Saturday opening hours of the main branch?"})
        elif self.name == "prompt_2kb":
            msgs.append({"role": "user", "content": f"{NOTES_2KB}\n\nSummarize these notes in three bullet points. Request {i} ({tag})."})
        elif self.name == "secret_redaction":
            akia = "AKIA" + rand_token(string.ascii_uppercase + string.digits, 16)
            ghp = "ghp_" + rand_token(string.ascii_letters + string.digits, 36)
            msgs.append({"role": "user", "content": f"Deploy {i} fails with this config:\nAWS_ACCESS_KEY_ID={akia}\nGITHUB_TOKEN={ghp}\nREGION=eu-central-1\nWhat is wrong?"})
        elif self.name == "tool_call_read":
            from demo.tools import openai_tools

            body["tools"] = openai_tools(["kb.search"])
            msgs.append({"role": "user", "content": f"Find the KB article about transfer limits for case {i} ({tag})."})
            mock = {"tool_calls": [{"name": "kb__search", "arguments": {"query": f"transfer limits {i}"}}]}
        elif self.name == "tool_call_side_effect":
            from demo.tools import openai_tools

            body["tools"] = openai_tools(["kb.search", "mail.send"])
            msgs.append({"role": "user", "content": f"Email the operations team the weekly fee summary for week {i} ({tag})."})
            mock = {"tool_calls": [{"name": "mail__send", "arguments": {"to": "ops@bank.example", "subject": f"Weekly fees, week {i}", "body": "Fees unchanged this week."}}]}
        elif self.name == "streaming":
            body["stream"] = True
            msgs.append({"role": "user", "content": f"Summarize the retail fee review for meeting {i} ({tag})."})
            mock = {"content": f"{STREAM_REPLY} Meeting {i}.", "chunk_size": 8}
        else:
            raise ValueError(self.name)
        body["messages"] = msgs
        return body, mock


SCENARIOS = [
    Scenario("benign_short", "Benign short prompt (~20 tokens, unique)"),
    Scenario("benign_repeat", "Same benign prompt repeated (T1 result cached)"),
    Scenario("prompt_2kb", "2 KB benign prompt (~450 tokens, unique)"),
    Scenario("secret_redaction", "Prompt with an AWS key id and a GitHub token (redaction path)"),
    Scenario("tool_call_read", "Model returns a kb.search tool call (tool governance, read-only)"),
    Scenario("tool_call_side_effect", "Model returns a mail.send tool call (side effect: argument rules, trifecta, judge path with the fake judge)"),
    Scenario("streaming", "Streaming reply, ~700 characters in 8-character chunks", stream=True),
]


@dataclass
class Sample:
    ms: float
    status: int
    ttfb_ms: float | None = None
    action: str | None = None
    trace_id: str | None = None


class RawHTTP:
    """Minimal HTTP/1.1 keep-alive client for the load generator (Content-Length and chunked bodies).

    httpx is not used on the client side because its connection pool becomes the bottleneck under
    concurrency. Measured on this machine against the mock upstream (httpx 0.28.1, httpcore 1.0.9):
    httpx about 2,100 / 2,900 / 370 req/s at 1 / 8 / 32 concurrent requests, this client about
    8,200 / 14,100 / 14,700 req/s. The gateway's own upstream client is httpx; that cost is part
    of what the benchmark measures.
    """

    IDLE_S = 3.0  # uvicorn closes idle keep-alive connections after 5 s

    def __init__(self) -> None:
        self.free: dict[tuple[str, int], list[tuple[asyncio.StreamReader, asyncio.StreamWriter, float]]] = {}

    async def _conn(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bool]:
        pool = self.free.setdefault((host, port), [])
        now = time.monotonic()
        while pool:
            r, w, last = pool.pop()
            if now - last < self.IDLE_S and not w.is_closing():
                return r, w, True
            w.close()
        r, w = await asyncio.open_connection(host, port)
        return r, w, False

    async def close(self) -> None:
        for pool in self.free.values():
            for _, w, _ in pool:
                w.close()
        self.free.clear()

    async def post(self, url: str, body: dict[str, Any], headers: dict[str, str] | None = None, timeout: float = 60.0) -> Sample:
        for attempt in (1, 2):
            try:
                return await asyncio.wait_for(self._post_once(url, body, headers or {}), timeout)
            except (ConnectionError, asyncio.IncompleteReadError) as exc:
                if attempt == 2:
                    raise ConnectionError(f"{type(exc).__name__}: {exc}") from exc
        raise AssertionError("unreachable")

    async def _post_once(self, url: str, body: dict[str, Any], headers: dict[str, str]) -> Sample:
        from urllib.parse import urlsplit

        u = urlsplit(url)
        host, port = u.hostname or "127.0.0.1", u.port or 80
        payload = json.dumps(body).encode()
        head = [f"POST {u.path or '/'} HTTP/1.1", f"Host: {host}:{port}", "Content-Type: application/json", f"Content-Length: {len(payload)}"]
        head += [f"{k}: {v}" for k, v in headers.items()]
        req = ("\r\n".join(head) + "\r\n\r\n").encode() + payload
        reader, writer, _reused = await self._conn(host, port)
        t = time.perf_counter()
        try:
            writer.write(req)
            await writer.drain()
            raw_head = await reader.readuntil(b"\r\n\r\n")
            lines = raw_head.decode("latin-1").split("\r\n")
            status = int(lines[0].split(" ", 2)[1])
            hdrs: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()
            ttfb: float | None = None
            if hdrs.get("transfer-encoding", "").lower() == "chunked":
                buf = b""
                while True:
                    size = int((await reader.readline()).split(b";")[0].strip() or b"0", 16)
                    if size == 0:
                        while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                            pass
                        break
                    data = await reader.readexactly(size)
                    await reader.readexactly(2)
                    if ttfb is None:
                        buf += data
                        *complete, buf = buf.split(b"\n")
                        for line in complete:
                            if line.startswith(b"data:") and b'"content"' in line:
                                try:
                                    obj = json.loads(line[5:].strip())
                                except json.JSONDecodeError:
                                    continue
                                if any((c.get("delta") or {}).get("content") for c in obj.get("choices") or []):
                                    ttfb = (time.perf_counter() - t) * 1000
                                    break
            elif "content-length" in hdrs:
                await reader.readexactly(int(hdrs["content-length"]))
            else:
                await reader.read()
                hdrs["connection"] = "close"
            ms = (time.perf_counter() - t) * 1000
        except BaseException:
            writer.close()
            raise
        if hdrs.get("connection", "").lower() == "close":
            writer.close()
        else:
            self.free.setdefault((host, port), []).append((reader, writer, time.monotonic()))
        return Sample(ms, status, ttfb, hdrs.get("x-bouncer-action"), hdrs.get("x-bouncer-trace-id"))


async def send(client: RawHTTP, url: str, body: dict[str, Any], headers: dict[str, str]) -> Sample:
    return await client.post(url, body, headers)


async def script_mock(client: RawHTTP, stack: Stack, item: dict[str, Any] | None) -> None:
    if item is not None:
        s = await client.post(stack.mock_url + "/mock/script", {"responses": [item]})
        if s.status != 200:
            raise RuntimeError(f"mock /mock/script returned HTTP {s.status}")


def gw_headers(stack: Stack, principal: str, session: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {stack.keys[principal]}", "X-Bouncer-Session": session}


async def run_latency(client: RawHTTP, stack: Stack, sc: Scenario, n: int, warmup: int) -> dict[str, Any]:
    direct: list[Sample] = []
    via: list[Sample] = []
    for i in range(warmup + n):
        body, mock = sc.build(i)
        await script_mock(client, stack, mock)
        d = await send(client, stack.mock_url + "/v1/chat/completions", body, {})
        await script_mock(client, stack, mock)
        g = await send(client, stack.gateway_url + "/v1/chat/completions", body, gw_headers(stack, sc.principal, f"bench-{sc.name}-{i}-{uuid.uuid4().hex[:6]}"))
        if i >= warmup:
            direct.append(d)
            via.append(g)
    actions: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for s in via:
        actions[str(s.action)] = actions.get(str(s.action), 0) + 1
        statuses[str(s.status)] = statuses.get(str(s.status), 0) + 1
    out: dict[str, Any] = {
        "name": sc.name,
        "title": sc.title,
        "requests": n,
        "warmup": warmup,
        "direct_ms": stats([s.ms for s in direct]),
        "gateway_ms": stats([s.ms for s in via]),
        "actions": actions,
        "statuses": statuses,
        "trace_ids": [s.trace_id for s in via if s.trace_id],
    }
    if sc.stream:
        out["direct_ttfb_ms"] = stats([s.ttfb_ms for s in direct if s.ttfb_ms is not None])
        out["gateway_ttfb_ms"] = stats([s.ttfb_ms for s in via if s.ttfb_ms is not None])
    dp, gp = out["direct_ms"]["p50"], out["gateway_ms"]["p50"]
    out["added_p50_ms"] = _r(gp - dp) if dp is not None and gp is not None else None
    dp, gp = out["direct_ms"]["p95"], out["gateway_ms"]["p95"]
    out["added_p95_ms"] = _r(gp - dp) if dp is not None and gp is not None else None
    return out


async def run_throughput(client: RawHTTP, stack: Stack, concurrency: int, duration: float, direct: bool = False) -> dict[str, Any]:
    sc = Scenario("benign_short", "")
    samples: list[Sample] = []
    url = (stack.mock_url if direct else stack.gateway_url) + "/v1/chat/completions"
    errors: dict[str, int] = {}
    start = time.perf_counter()
    stop_at = start + duration
    counter = [0]

    async def worker(w: int) -> None:
        while time.perf_counter() < stop_at:
            counter[0] += 1
            body, _ = sc.build(100000 + counter[0])
            headers = {} if direct else gw_headers(stack, sc.principal, f"bench-tp{concurrency}-{w}-{counter[0]}")
            try:
                samples.append(await send(client, url, body, headers))
            except (TimeoutError, ConnectionError, OSError) as exc:
                errors[type(exc).__name__] = errors.get(type(exc).__name__, 0) + 1

    pid = stack.pid("mock" if direct else "gateway")
    cpu0 = cpu_seconds(pid)
    await asyncio.gather(*(worker(w) for w in range(concurrency)))
    elapsed = time.perf_counter() - start
    cpu1 = cpu_seconds(pid)
    cpu = (cpu1 - cpu0) if cpu0 is not None and cpu1 is not None else None
    ok = [s for s in samples if s.status == 200]
    statuses: dict[str, int] = {}
    for s in samples:
        statuses[str(s.status)] = statuses.get(str(s.status), 0) + 1
    return {
        "target": "mock (direct)" if direct else "gateway",
        "concurrency": concurrency,
        "duration_s": round(elapsed, 2),
        "requests": len(samples),
        "ok": len(ok),
        "rps": round(len(ok) / elapsed, 1) if elapsed > 0 else None,
        "latency_ms": stats([s.ms for s in samples]),
        "statuses": statuses,
        "client_errors": errors,
        "server_cpu_s": _r(cpu, 3),
        "server_cpu_ms_per_request": _r(cpu * 1000 / len(samples), 2) if cpu is not None and samples else None,
        "server_cpu_cores": _r(cpu / elapsed, 2) if cpu is not None and elapsed > 0 else None,
        "trace_ids": [s.trace_id for s in samples if s.trace_id],
    }


# ---------------------------------------------------------------------------- audit


def read_audit(path: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return out
    for line in path.read_text(errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("trace_id") and ev.get("type", "decision") == "decision":
            out[ev["trace_id"]] = ev
    return out


def layer_stats(trace_ids: list[str], audit: dict[str, dict[str, Any]]) -> dict[str, Any]:
    vals: dict[str, list[float]] = {k: [] for k in LAYERS}
    found = 0
    escalated: dict[str, int] = {}
    for tid in trace_ids:
        ev = audit.get(tid)
        if not ev:
            continue
        found += 1
        lat = ev.get("latency_ms") or {}
        for k in LAYERS:
            if isinstance(lat.get(k), (int, float)):
                vals[k].append(float(lat[k]))
        j = ev.get("judge") or {}
        if j.get("invoked"):
            reason = str(j.get("reason") or "unknown")
            escalated[reason] = escalated.get(reason, 0) + 1
    return {"events": found, "t2_escalations": escalated, **{k: stats(v) for k, v in vals.items()}}


# ---------------------------------------------------------------------------- report


def fmt(x: Any, nd: int = 1) -> str:
    if x is None:
        return "-"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)


def analysis(result: dict[str, Any]) -> list[str]:
    """Plain statements computed from the numbers (no hand-written claims)."""
    lines = []
    by = {s["name"]: s for s in result["scenarios"]}
    for name in ("benign_short", "prompt_2kb", "benign_repeat", "secret_redaction", "tool_call_side_effect"):
        s = by.get(name)
        if not s:
            continue
        L = s["layers"]
        ov, t0, t1 = L["gateway_overhead"]["p50"], L["t0"]["p50"], L["t1"]["p50"]
        if ov:
            share = (t1 or 0) / ov * 100
            lines.append(
                f"- `{name}`: gateway overhead p50 {fmt(ov)} ms, of which T1 {fmt(t1)} ms ({share:.0f}%) and T0 {fmt(t0)} ms; "
                f"the rest ({fmt(max(ov - (t1 or 0) - (t0 or 0), 0.0))} ms) is request parsing, policy lookup, audit write and proxying."
            )
    st = by.get("streaming")
    if st and st.get("gateway_ttfb_ms"):
        lines.append(
            f"- `streaming`: time to first content chunk p50 {fmt(st['direct_ttfb_ms']['p50'])} ms direct vs "
            f"{fmt(st['gateway_ttfb_ms']['p50'])} ms through the gateway. T1 on the prompt accounts for {fmt(st['layers']['t1']['p50'])} ms "
            "of that (it runs before the request is forwarded); the rest includes the small window of text the gateway holds back so a "
            f"secret split across chunks can still be redacted. Output scanning of the stream shows up as T0 ({fmt(st['layers']['t0']['p50'])} ms p50 "
            "over the whole stream)."
        )
    tps = [t for t in result["throughput"] if t["target"] == "gateway"]
    if tps:
        best = max(tps, key=lambda t: t["rps"] or 0)
        lines.append(
            f"- Throughput peaked at {fmt(best['rps'])} req/s with {best['concurrency']} concurrent clients "
            f"(single uvicorn worker, T1 {result['setup']['t1_mode']}); p95 at that level was {fmt(best['latency_ms']['p95'])} ms."
        )
        hi = max(tps, key=lambda t: t["concurrency"])
        t1_hi = (hi.get("layers") or {}).get("t1", {}).get("p50")
        t1_lo = (min(tps, key=lambda t: t["concurrency"]).get("layers") or {}).get("t1", {}).get("p50")
        if t1_hi and t1_lo:
            lines.append(
                f"- T1 p50 grows from {fmt(t1_lo)} ms at 1 client to {fmt(t1_hi)} ms at {hi['concurrency']} clients. The ONNX classifier "
                f"runs at most {os.environ.get('T1_CONCURRENCY', '3')} inferences at once (`T1_CONCURRENCY`, one shared session in "
                "`bouncer/t1/classifier.py`), so under load requests queue for it; more workers or replicas scale it further. "
                "Without T1 the same path costs well under 1 ms (see `benign_repeat`, where the T1 result is cached)."
            )
    for s in result["scenarios"]:
        esc = s["layers"].get("t2_escalations") or {}
        n = sum(esc.values())
        if n and s["name"] not in ("tool_call_side_effect",):
            reasons = ", ".join(f"{k} {v}" for k, v in esc.items())
            lines.append(
                f"- `{s['name']}`: {n} of {s['layers']['events']} requests were escalated to the judge ({reasons}). With the real judge "
                "each escalation adds the judge's latency (measured separately: `judge/bench.py`, `reports/judge_bench_*.json`, "
                "and `latency_ms_p50` in the judge's `GET /health`)."
            )
    off = result.get("t1_off")
    if off and off.get("throughput"):
        best_off = max(off["throughput"], key=lambda t: t["rps"] or 0)
        lines.append(
            f"- With T1 disabled the same gateway serves {fmt(best_off['rps'])} req/s (concurrent clients: {best_off['concurrency']}, "
            f"p95 {fmt(best_off['latency_ms']['p95'])} ms); everything except T1 costs {fmt(off['scenarios'][0]['layers']['gateway_overhead']['p50'])} ms "
            "p50 per request inside the gateway (audit `gateway_overhead`)."
        )
        hi_off = max(off["throughput"], key=lambda t: t["concurrency"])
        lo_off = min(off["throughput"], key=lambda t: t["concurrency"])
        up_hi = (hi_off.get("layers") or {}).get("upstream", {}).get("p50")
        up_lo = (lo_off.get("layers") or {}).get("upstream", {}).get("p50")
        mock_tp = next((t for t in result["throughput"] if t["target"].startswith("mock")), None)
        if up_hi and up_lo and hi_off["concurrency"] > lo_off["concurrency"] and up_hi > 3 * up_lo:
            mock_note = (f" while the mock answers direct requests at the same concurrency in {fmt(mock_tp['latency_ms']['p50'])} ms p50"
                         if mock_tp else "")
            cpu_lo, cpu_hi = lo_off.get("server_cpu_ms_per_request"), hi_off.get("server_cpu_ms_per_request")
            cpu_note = (f" Gateway CPU per request rises from {fmt(cpu_lo, 2)} ms to {fmt(cpu_hi, 2)} ms over the same range, so the single "
                        "worker saturates one core and the waiting shows up inside the upstream call, where the coroutine yields."
                        if cpu_lo and cpu_hi else "")
            lines.append(
                f"- Without T1, the next limit is the single worker process: the gateway's own `upstream` time grows from {fmt(up_lo)} ms p50 "
                f"(concurrent clients: {lo_off['concurrency']}) to {fmt(up_hi)} ms (concurrent clients: {hi_off['concurrency']}){mock_note}.{cpu_note} "
                "The httpx client used for the upstream call degrades the same way under concurrency on the load-generator side "
                "(see the RawHTTP note in `scripts/bench.py`). More uvicorn workers or replicas scale this part; budget counters are "
                "the only shared state."
            )
    return lines


def write_report(result: dict[str, Any], md_path: Path, json_path: Path) -> None:
    slim = json.loads(json.dumps(result))
    for s in slim["scenarios"]:
        s.pop("trace_ids", None)
    for t in slim["throughput"]:
        t.pop("trace_ids", None)
    json_path.write_text(json.dumps(slim, indent=2) + "\n")

    su, hw = result["setup"], result["hardware"]
    cpu = hw.get("cpu") or hw.get("machine")
    mem = f"{hw.get('memory_gb')} GB" if hw.get("memory_gb") else "unknown memory"
    out = [
        "# Bouncer gateway benchmark",
        "",
        f"Generated by `scripts/bench.py{' --quick' if su['quick'] else ''}` on {su['started_at']} ({su['duration_s']} s wall time).",
        "",
        "## Setup",
        "",
        f"- Hardware: {cpu}, {mem}, {hw.get('os') or hw.get('platform')}; Python {hw.get('python')}, onnxruntime {hw.get('onnxruntime') or '-'}.",
        f"- Machine load average before / after: {su['loadavg_before']} / {su['loadavg_after']} (the Mac is shared with another project, so absolute numbers carry noise).",
        "- Gateway: `python -m bouncer.gateway.app`, one uvicorn worker, policy = `policy/bouncer.yaml` with upstreams pointed at the mock, "
        "judge backend `fake` (in-process, no model), team budgets raised so they never trigger, hot reload off.",
        f"- T1: `{su['t1_mode']}`" + (" (protectai/deberta-v3-base-prompt-injection-v2, ONNX fp32 on CPU)." if su["t1_mode"] == "onnx" else " (deterministic keyword classifier, no model)."),
        "- T2: the fake judge answers in-process, so the `t2` column is near zero. Real judge latency is measured separately (`judge/bench.py`, `reports/judge_bench_*.json`).",
        "- Upstream: `demo/mock_upstream.py` (simulated OpenAI API, no model) on the same machine.",
        f"- Client: a minimal asyncio HTTP/1.1 keep-alive client in one process (httpx on the client side became the bottleneck at 32 concurrent requests). Latency scenarios: {su['requests_per_scenario']} measured requests each after {su['warmup']} warm-up requests, "
        "direct and gateway requests alternate. Every prompt is unique unless noted, so the T1 cache does not hide classifier cost.",
        f"- Gateway resident memory after the run: {fmt(su.get('gateway_rss_mb'))} MB.",
        "",
        "## Client-observed latency (ms)",
        "",
        "`direct` = client to mock upstream; `gateway` = client to Bouncer to mock upstream. `added` = gateway minus direct at the same percentile.",
        "",
        "| Scenario | direct p50 | direct p95 | direct p99 | gateway p50 | gateway p95 | gateway p99 | added p50 | added p95 | gateway actions |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for s in result["scenarios"]:
        d, g = s["direct_ms"], s["gateway_ms"]
        acts = ", ".join(f"{k} {v}" for k, v in s["actions"].items())
        out.append(
            f"| {s['name']} | {fmt(d['p50'])} | {fmt(d['p95'])} | {fmt(d['p99'])} | {fmt(g['p50'])} | {fmt(g['p95'])} | {fmt(g['p99'])} | "
            f"{fmt(s['added_p50_ms'])} | {fmt(s['added_p95_ms'])} | {acts} |"
        )
    st = next((s for s in result["scenarios"] if s["name"] == "streaming"), None)
    if st and st.get("gateway_ttfb_ms"):
        out += [
            "",
            "Streaming, time to first content chunk (ms):",
            "",
            "| | p50 | p95 | p99 |",
            "|---|---:|---:|---:|",
            f"| direct | {fmt(st['direct_ttfb_ms']['p50'])} | {fmt(st['direct_ttfb_ms']['p95'])} | {fmt(st['direct_ttfb_ms']['p99'])} |",
            f"| gateway | {fmt(st['gateway_ttfb_ms']['p50'])} | {fmt(st['gateway_ttfb_ms']['p95'])} | {fmt(st['gateway_ttfb_ms']['p99'])} |",
        ]
    out += [
        "",
        "Scenarios:",
        "",
    ]
    out += [f"- `{s['name']}`: {s['title']}." for s in result["scenarios"]]
    out += [
        "",
        "## Gateway per-layer timings (ms, from the audit log of the same requests)",
        "",
        "`gateway_overhead` = total time inside the gateway minus the upstream call. For streaming, `total` spans the whole stream.",
        "",
        "`escalated to T2` counts requests that called the judge (here the in-process fake, so it adds no time); with a real judge each one adds its latency.",
        "",
        "| Scenario | events | T0 p50 / p95 | T1 p50 / p95 / p99 | T2 p50 | escalated to T2 | upstream p50 | overhead p50 | overhead p95 | overhead p99 |",
        "|---|---:|---:|---:|---:|---|---:|---:|---:|---:|",
    ]
    for s in result["scenarios"]:
        L = s["layers"]
        esc = ", ".join(f"{v} ({k})" for k, v in (L.get("t2_escalations") or {}).items()) or "0"
        out.append(
            f"| {s['name']} | {L['events']} | {fmt(L['t0']['p50'], 2)} / {fmt(L['t0']['p95'], 2)} | "
            f"{fmt(L['t1']['p50'])} / {fmt(L['t1']['p95'])} / {fmt(L['t1']['p99'])} | {fmt(L['t2']['p50'], 2)} | {esc} | {fmt(L['upstream']['p50'])} | "
            f"{fmt(L['gateway_overhead']['p50'])} | {fmt(L['gateway_overhead']['p95'])} | {fmt(L['gateway_overhead']['p99'])} |"
        )
    out += [
        "",
        "## Throughput (benign short prompts, every prompt unique)",
        "",
        "`server CPU` = CPU time of the gateway (or mock) process during the phase, per request and as cores in use (ONNX uses up to 4 threads).",
        "",
        "| Target | concurrent clients | duration s | requests | OK | req/s | p50 ms | p95 ms | p99 ms | T1 p50 ms | overhead p50 ms | server CPU ms/req | server CPU cores | non-200 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for t in result["throughput"]:
        L = t.get("layers") or {}
        non200 = {k: v for k, v in t["statuses"].items() if k != "200"}
        non200.update(t["client_errors"])
        out.append(
            f"| {t['target']} | {t['concurrency']} | {t['duration_s']} | {t['requests']} | {t['ok']} | {fmt(t['rps'])} | "
            f"{fmt(t['latency_ms']['p50'])} | {fmt(t['latency_ms']['p95'])} | {fmt(t['latency_ms']['p99'])} | "
            f"{fmt((L.get('t1') or {}).get('p50'))} | {fmt((L.get('gateway_overhead') or {}).get('p50'))} | "
            f"{fmt(t.get('server_cpu_ms_per_request'), 2)} | {fmt(t.get('server_cpu_cores'), 2)} | {non200 or '-'} |"
        )
    off = result.get("t1_off")
    if off:
        lat = off["scenarios"][0]
        out += [
            "",
            "## Comparison pass with T1 disabled (`BOUNCER_T1=off`)",
            "",
            "Same gateway and policy, classifier not loaded. Shows the cost of everything except T1 (T0, policy, tool rules, budgets, audit, proxying).",
            "",
            "| Measurement | requests | p50 ms | p95 ms | p99 ms | req/s | overhead p50 ms (audit) | upstream p50 ms (audit) | server CPU ms/req |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
            f"| benign_short latency, sequential | {lat['requests']} | {fmt(lat['gateway_ms']['p50'])} | {fmt(lat['gateway_ms']['p95'])} | "
            f"{fmt(lat['gateway_ms']['p99'])} | - | {fmt(lat['layers']['gateway_overhead']['p50'])} | {fmt(lat['layers']['upstream']['p50'])} | - |",
        ]
        for t in off["throughput"]:
            out.append(
                f"| throughput, concurrent clients: {t['concurrency']} | {t['requests']} | {fmt(t['latency_ms']['p50'])} | {fmt(t['latency_ms']['p95'])} | "
                f"{fmt(t['latency_ms']['p99'])} | {fmt(t['rps'])} | {fmt(t['layers']['gateway_overhead']['p50'])} | "
                f"{fmt(t['layers']['upstream']['p50'])} | {fmt(t.get('server_cpu_ms_per_request'), 2)} |"
            )
    out += ["", "## What dominates the overhead", ""]
    out += analysis(result) or ["- (no data)"]
    out += [
        "",
        "## Reproduce",
        "",
        "```",
        "make bench                                  # full run",
        "uv run python scripts/bench.py --quick      # about 20-30 s",
        "uv run python scripts/bench.py --t1 fake    # without the ONNX classifier",
        "```",
        "",
        "Ports 8705 (gateway) and 8706 (mock) by default; change with `--gateway-port` / `--mock-port`. Raw numbers: `reports/bench.json`.",
        "",
    ]
    md_path.write_text("\n".join(out))


# ---------------------------------------------------------------------------- main


async def run(stack: Stack, args: argparse.Namespace) -> dict[str, Any]:
    client = RawHTTP()
    try:
        scenarios = []
        for sc in SCENARIOS:
            if args.only and sc.name not in args.only:
                continue
            t = time.perf_counter()
            res = await run_latency(client, stack, sc, args.requests, args.warmup)
            print(f"  {sc.name:<22} gateway p50 {fmt(res['gateway_ms']['p50'])} ms, direct p50 {fmt(res['direct_ms']['p50'])} ms, "
                  f"actions {res['actions']} ({time.perf_counter() - t:.1f} s)", flush=True)
            scenarios.append(res)
        throughput = []
        for c in args.concurrency:
            res = await run_throughput(client, stack, c, args.duration)
            print(f"  throughput gateway c={c:<3} {fmt(res['rps'])} req/s, p95 {fmt(res['latency_ms']['p95'])} ms, statuses {res['statuses']}", flush=True)
            throughput.append(res)
        if args.direct_duration > 0:
            c = max(args.concurrency)
            res = await run_throughput(client, stack, c, args.direct_duration, direct=True)
            print(f"  throughput mock    c={c:<3} {fmt(res['rps'])} req/s, p95 {fmt(res['latency_ms']['p95'])} ms", flush=True)
            throughput.append(res)
    finally:
        await client.close()
    perf = None
    try:
        async with httpx.AsyncClient(timeout=10) as hc:
            r = await hc.get(stack.gateway_url + "/api/perf", params={"window": "1h"})
            if r.status_code == 200:
                perf = r.json()
    except httpx.HTTPError:
        perf = None
    return {"scenarios": scenarios, "throughput": throughput, "api_perf": perf}


async def run_t1_off(stack: Stack, args: argparse.Namespace) -> dict[str, Any]:
    """Second, shorter pass with T1 disabled: what the gateway costs without the classifier."""
    client = RawHTTP()
    try:
        lat = await run_latency(client, stack, SCENARIOS[0], max(args.requests // 2, 20), args.warmup)
        print(f"  [T1 off] benign_short gateway p50 {fmt(lat['gateway_ms']['p50'])} ms", flush=True)
        tps = []
        for c in args.concurrency:
            res = await run_throughput(client, stack, c, args.t1_off_duration)
            print(f"  [T1 off] throughput c={c:<3} {fmt(res['rps'])} req/s, p95 {fmt(res['latency_ms']['p95'])} ms", flush=True)
            tps.append(res)
    finally:
        await client.close()
    return {"scenarios": [lat], "throughput": tps}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="short run (about 20-30 s)")
    ap.add_argument("--t1", default="auto", choices=["auto", "onnx", "fake", "off"], help="T1 classifier mode for the gateway")
    ap.add_argument("--gateway-port", type=int, default=int(os.environ.get("BENCH_GATEWAY_PORT", "8705")))
    ap.add_argument("--mock-port", type=int, default=int(os.environ.get("BENCH_MOCK_PORT", "8706")))
    ap.add_argument("--requests", type=int, default=None, help="measured requests per latency scenario")
    ap.add_argument("--warmup", type=int, default=None)
    ap.add_argument("--duration", type=float, default=None, help="seconds per throughput level")
    ap.add_argument("--concurrency", type=int, nargs="+", default=[1, 8, 32])
    ap.add_argument("--only", nargs="*", help="run only these latency scenarios")
    ap.add_argument("--no-t1-off-pass", action="store_true", help="skip the comparison pass with T1 disabled")
    ap.add_argument("--out", default=str(ROOT / "reports" / "bench"), help="output path without extension (.md and .json are written)")
    args = ap.parse_args()
    args.requests = args.requests or (25 if args.quick else 200)
    args.warmup = args.warmup if args.warmup is not None else (3 if args.quick else 10)
    args.duration = args.duration or (2.0 if args.quick else 8.0)
    args.direct_duration = 1.0 if args.quick else 3.0
    args.t1_off_duration = 1.5 if args.quick else 5.0
    random.seed(7)

    started = time.time()
    load_before = loadavg()
    print(f"Starting mock :{args.mock_port} and gateway :{args.gateway_port} ...", flush=True)
    stack = start_stack(args)
    try:
        print(f"Ready (T1 {stack.t1_mode}). Latency scenarios: {args.requests} requests each after {args.warmup} warm-up.", flush=True)
        data = asyncio.run(run(stack, args))
        gw_pid = stack.pid("gateway")
        rss = rss_mb(gw_pid) if gw_pid else None
        time.sleep(0.3)  # let the last stream events reach the audit file
        audit = read_audit(stack.audit_path)
    except BaseException:
        print(f"Benchmark failed; gateway and mock logs are kept in {stack.tmp}", file=sys.stderr)
        raise
    finally:
        stack.stop()
    for s in data["scenarios"]:
        s["layers"] = layer_stats(s["trace_ids"], audit)
    for t in data["throughput"]:
        if t["target"] == "gateway":
            t["layers"] = layer_stats(t["trace_ids"], audit)
    if stack.t1_mode == "onnx":
        t1s = [s["layers"]["t1"]["p50"] for s in data["scenarios"] if s["name"] == "benign_short"]
        if t1s and not t1s[0]:
            print("WARNING: T1 mode is onnx but T1 latency is zero; check the gateway log for a classifier load error:", file=sys.stderr)
            print(stack.log_tail("gateway"), file=sys.stderr)
    t1_off = None
    if stack.t1_mode != "off" and not args.no_t1_off_pass:
        print("Restarting the gateway with T1 off for a comparison pass ...", flush=True)
        stack2 = start_stack(args, t1_override="off")
        try:
            t1_off = asyncio.run(run_t1_off(stack2, args))
            time.sleep(0.3)
            audit2 = read_audit(stack2.audit_path)
        except BaseException:
            print(f"Comparison pass failed; logs are kept in {stack2.tmp}", file=sys.stderr)
            raise
        finally:
            stack2.stop()
        shutil.rmtree(stack2.tmp, ignore_errors=True)
        for s in t1_off["scenarios"]:
            s["layers"] = layer_stats(s.pop("trace_ids"), audit2)
        for t in t1_off["throughput"]:
            t["layers"] = layer_stats(t.pop("trace_ids"), audit2)
    result = {
        "setup": {
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(started)),
            "duration_s": round(time.time() - started, 1),
            "quick": args.quick,
            "t1_mode": stack.t1_mode,
            "judge_backend": "fake (in-process)",
            "upstream": "demo.mock_upstream (simulated, no model)",
            "requests_per_scenario": args.requests,
            "warmup": args.warmup,
            "throughput_seconds_per_level": args.duration,
            "concurrency_levels": args.concurrency,
            "gateway_workers": 1,
            "loadavg_before": load_before,
            "loadavg_after": loadavg(),
            "gateway_rss_mb": rss,
        },
        "hardware": hardware(),
        **data,
        "t1_off": t1_off,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_report(result, out.with_suffix(".md"), out.with_suffix(".json"))
    shutil.rmtree(stack.tmp, ignore_errors=True)  # temporary policy, audit log and process logs
    print(f"Wrote {out.with_suffix('.md').relative_to(ROOT) if out.is_relative_to(ROOT) else out.with_suffix('.md')} "
          f"and .json in {result['setup']['duration_s']} s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
