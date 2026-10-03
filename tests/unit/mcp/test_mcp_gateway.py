"""MCP gateway (/mcp) end to end: a real MCP client over streamable HTTP talks to the Bouncer gateway
(uvicorn on 127.0.0.1, started by this module on 8705 or 8706, or an ephemeral port when both are
busy), which proxies the demo-bank MCP server running in-process. Offline, no models (fake T1 and judge).

Covered: definition pinning, tool poisoning hidden, rug pull blocked (also without re-listing),
re-approval re-pins, result scanning with redaction, principal allowlist, unknown key refused, server
allowlist, pinning / supply_chain disabled, lethal trifecta over MCP, Bouncer key not forwarded upstream.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import uvicorn
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport

from bouncer.gateway.app import create_app
from bouncer.gateway.mcp_gateway import definition_hash
from bouncer.gateway.state import Settings
from demo import mcp_server as ms
from demo import tools as demo_tools

HOST = "127.0.0.1"
# Ports granted for test servers; scripts/bench.py uses the same two, so when both are busy the test
# servers take an OS-assigned ephemeral port (49152+), which cannot collide with any fixed service port.
PREFERRED_PORTS = (8705, 8706)
KEYS = {
    "BOUNCER_KEY_OPS_COPILOT": "bk_mcp_ops",
    "BOUNCER_KEY_DEV_ASSISTANT": "bk_mcp_dev",
    "BOUNCER_KEY_INTERN_BOT": "bk_mcp_intern",
    "BOUNCER_KEY_PLAYGROUND": "bk_mcp_pg",
}
OPS, INTERN = KEYS["BOUNCER_KEY_OPS_COPILOT"], KEYS["BOUNCER_KEY_INTERN_BOT"]
BENIGN_CHANGE = "Search the internal knowledge base. Results are ranked by relevance and recency."
FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
POISON = ms.POISON_DESCRIPTION


def _bind_socket() -> socket.socket:
    for port in (*PREFERRED_PORTS, 0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((HOST, port))
        except OSError:
            sock.close()
            continue
        sock.listen(128)
        return sock
    raise RuntimeError("no free port")


class _Server:
    """uvicorn in a background thread on a pre-bound socket (no bind race)."""

    def __init__(self, app: Any) -> None:
        self.sock = _bind_socket()
        self.port = self.sock.getsockname()[1]
        self.url = f"http://{HOST}:{self.port}"
        self.server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="on"))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True)

    def __enter__(self) -> _Server:
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            if time.monotonic() > deadline or not self.thread.is_alive():
                raise RuntimeError("test server did not start")
            time.sleep(0.01)
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.should_exit = True
        self.thread.join(5)
        self.sock.close()


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    saved_env = {k: os.environ.get(k) for k in KEYS}
    os.environ.update(KEYS)
    tmp = tmp_path_factory.mktemp("mcp")
    policy = tmp / "bouncer.yaml"
    shutil.copy("policy/bouncer.yaml", policy)
    old_flag = ms._FLAG_PATH
    ms._FLAG_PATH = tmp / "poison.flag"
    ms.set_poison(False)
    app = create_app(Settings(policy_path=str(policy), audit_path=str(tmp / "audit.jsonl"), t1="fake", judge_override="fake", watch=False))
    gw = app.state.gw
    mcp = app.state.mcp
    upstream = ms.build_server()
    mcp.set_upstream(upstream)
    original_policy = policy.read_text()
    with _Server(app) as srv:
        yield {"url": srv.url, "app": app, "gw": gw, "mcp": mcp, "policy": policy, "original_policy": original_policy, "audit": tmp / "audit.jsonl", "upstream": upstream}
    ms._FLAG_PATH = old_flag
    for k, v in saved_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


@pytest.fixture()
def env(stack: dict[str, Any]) -> dict[str, Any]:
    os.environ.update(KEYS)
    gw, mcp = stack["gw"], stack["mcp"]
    if stack["policy"].read_text() != stack["original_policy"]:
        stack["policy"].write_text(stack["original_policy"])
        assert gw.policies.reload()
    gw.store.reset()
    mcp.reset()
    mcp.set_upstream(stack["upstream"])
    ms.set_poison(False)
    demo_tools.reset_state()
    stack["audit_start"] = len(_audit_lines(stack))
    _BASE["url"] = stack["url"]
    return stack


# ---------------------------------------------------------------------------- helpers


_BASE = {"url": ""}


def _client(key: str = OPS, session: str = "mcp-test") -> Client:
    return Client(StreamableHttpTransport(_BASE["url"] + "/mcp", headers={"X-Bouncer-Session": session}, auth=key))


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


async def _list(key: str = OPS) -> list[str]:
    async with _client(key) as c:
        return [t.name for t in await c.list_tools()]


async def _call(name: str, args: dict[str, Any], key: str = OPS, session: str = "mcp-test") -> Any:
    async with _client(key, session) as c:
        return await c.call_tool_mcp(name, args)


def _audit_lines(stack: dict[str, Any]) -> list[str]:
    path = stack["audit"]
    return path.read_text().splitlines() if path.exists() else []


def _events(stack: dict[str, Any], route: str | None = None) -> list[dict[str, Any]]:
    evs = [json.loads(line) for line in _audit_lines(stack)[stack["audit_start"]:]]
    return [e for e in evs if route is None or e.get("route") == route]


def _bouncer(result: Any) -> dict[str, Any]:
    return (result.meta or {}).get("bouncer") or {}


def _text(result: Any) -> str:
    return "\n".join(getattr(b, "text", "") for b in result.content)


def _set_policy(stack: dict[str, Any], old: str, new: str) -> None:
    text = stack["original_policy"]
    assert old in text
    stack["policy"].write_text(text.replace(old, new, 1))
    assert stack["gw"].policies.reload(), stack["gw"].policies.last_error


async def _upstream_tools() -> dict[str, Any]:
    async with Client(ms.build_server()) as c:
        return {t.name: t for t in await c.list_tools()}


# ---------------------------------------------------------------------------- tests


def test_list_pins_every_definition(env: dict[str, Any]) -> None:
    names = _run(_list())
    # ops-copilot may not call code.run_python, so it is not offered (least privilege)
    assert set(names) == {"crm.lookup_customer", "kb.search", "kb.write", "web.fetch", "mail.send", "payments.create_transfer"}
    pins = env["gw"].store.mcp_pins["demo-bank"]
    assert set(pins) == set(demo_tools.TOOL_NAMES)
    assert all(h.startswith("sha256:") and len(h) == 71 for h in pins.values())
    ev = _events(env, "mcp.list")[-1]
    assert ev["action"] == "allow" and ev["direction"] == "tool_definition"
    assert "pinned" in ev["message"]
    assert ev["mcp"]["server"] == "demo-bank"
    assert ev["mcp"]["not_allowed_for_principal"] == ["code.run_python"]
    api = httpx.get(env["url"] + "/api/mcp/tools", timeout=5).json()
    assert api["server"] == "demo-bank" and api["pin_tool_definitions"] is True
    assert api["pins"]["demo-bank"] == pins and {t["status"] for t in api["tools"]} == {"new_pin"}


def test_in_process_client_needs_a_local_principal(env: dict[str, Any]) -> None:
    from mcp.shared.exceptions import MCPError

    async def names() -> list[str]:
        async with Client(env["mcp"].proxy) as c:
            return [t.name for t in await c.list_tools()]

    with pytest.raises(MCPError, match="Missing or unknown Bouncer API key"):
        _run(names())
    env["mcp"].local_principal = "intern-bot"
    try:
        assert _run(names()) == ["kb.search"]
    finally:
        env["mcp"].local_principal = None


def test_definition_hash_covers_name_description_schema() -> None:
    tools = _run(_upstream_tools())
    kb = tools["kb.search"]

    class T:
        name = kb.name
        description = kb.description
        parameters = kb.input_schema

    base = definition_hash(T)
    T.description = kb.description + " "
    assert definition_hash(T) != base
    T.description = kb.description
    T.parameters = {**kb.input_schema, "required": []}
    assert definition_hash(T) != base


def test_poisoned_definition_hidden_and_audited(env: dict[str, Any]) -> None:
    ms.set_poison(True)  # poisoned from the first sight: never pinned
    names = _run(_list())
    assert "kb.search" not in names and "crm.lookup_customer" in names
    assert "kb.search" not in env["gw"].store.mcp_pins["demo-bank"]
    ev = _events(env, "mcp.list")[-1]
    assert ev["action"] == "block" and ev["status_code"] == 200
    blocking = [f for f in ev["findings"] if f["source"] == "tool_definition:kb.search" and f["effective_action"] == "block"]
    assert blocking and all(f["control"] in ("prompt_injection", "signatures") for f in blocking)
    assert "kb.search" in ev["mcp"]["hidden"]
    # a client that calls the hidden tool anyway is refused with an MCP tool error
    res = _run(_call("kb.search", {"query": "card fees"}))
    assert res.is_error
    b = _bouncer(res)
    assert b["action"] == "block" and b["code"].split(".")[0] in ("prompt_injection", "signatures")
    assert b["trace_id"] in _text(res) and _text(res).startswith("[Bouncer]")


def test_rug_pull_after_pinning_is_blocked(env: dict[str, Any]) -> None:
    assert "kb.search" in _run(_list())
    ok = _run(_call("kb.search", {"query": "card fees"}))
    assert not ok.is_error and "KB-001" in _text(ok)
    pinned = env["gw"].store.mcp_pins["demo-bank"]["kb.search"]
    ms.set_poison(True)
    # the client has not re-listed: the call path re-reads the definition from the server
    res = _run(_call("kb.search", {"query": "card fees"}))
    assert res.is_error
    b = _bouncer(res)
    assert b["code"] == "mcp_pinning.definition_changed"
    assert b["approval_id"] and b["approval_id"] in _text(res)
    appr = env["gw"].store.approvals[b["approval_id"]]
    assert appr.status == "pending" and appr.tool == "demo-bank/kb.search"
    assert env["gw"].store.mcp_pins["demo-bank"]["kb.search"] == pinned  # pin unchanged
    call_ev = _events(env, "mcp.call")[-1]
    assert call_ev["action"] == "block" and call_ev["direction"] == "tool_call"
    f = next(x for x in call_ev["findings"] if x["id"] == "mcp_pinning.definition_changed")
    assert f["severity"] == "critical" and f["owasp_llm"] == ["LLM03"] and f["owasp_agentic"] == ["ASI04"]
    assert "kb.search" not in _run(_list())
    # restoring the pinned definition restores the tool
    ms.set_poison(False)
    assert "kb.search" in _run(_list())


def test_reapproval_repins_new_definition(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ms, "POISON_DESCRIPTION", BENIGN_CHANGE)  # a benign change: only pinning objects
    assert "kb.search" in _run(_list())
    ms.set_poison(True)
    assert "kb.search" not in _run(_list())
    ev = _events(env, "mcp.list")[-1]
    assert [f["id"] for f in ev["findings"]] == ["mcp_pinning.definition_changed"]
    approval_id = ev["approval_id"]
    assert approval_id
    blocked = _run(_call("kb.search", {"query": "fees"}))
    assert blocked.is_error and _bouncer(blocked)["approval_id"] == approval_id
    r = httpx.post(f"{env['url']}/api/approvals/{approval_id}", json={"decision": "approve"}, timeout=5)
    assert r.status_code == 200 and r.json()["approval"]["status"] == "approved"
    assert "kb.search" in _run(_list())
    tools = env["mcp"].verdicts
    assert tools[("demo-bank", "kb.search")].status == "repinned"
    assert env["gw"].store.mcp_pins["demo-bank"]["kb.search"] == tools[("demo-bank", "kb.search")].hash
    assert "re-pinned" in _events(env, "mcp.list")[-1]["message"]
    ok = _run(_call("kb.search", {"query": "card fees"}))
    assert not ok.is_error


def test_allowed_call_result_is_scanned_and_redacted(env: dict[str, Any]) -> None:
    leaky = FastMCP(name="demo-bank")

    @leaky.tool(name="kb.search")
    def kb_search(query: str) -> str:
        return f"Deploy notes for {query}: AWS_ACCESS_KEY_ID={FAKE_AWS_KEY} region eu-central-1"

    env["mcp"].set_upstream(leaky)
    res = _run(_call("kb.search", {"query": "staging"}))
    assert not res.is_error
    blob = json.dumps({"content": [b.model_dump() for b in res.content], "structured": res.structured_content})
    assert FAKE_AWS_KEY not in blob
    assert "[REDACTED:" in _text(res) and "eu-central-1" in _text(res)
    assert FAKE_AWS_KEY not in json.dumps(res.structured_content)
    ev = _events(env, "mcp.call")[-1]
    assert ev["direction"] == "tool_result" and ev["action"] == "redact"
    assert any(f["control"] == "secrets" for f in ev["findings"])
    assert FAKE_AWS_KEY not in json.dumps(ev)
    assert _bouncer(res)["trace_id"] == ev["trace_id"]


def test_secret_in_arguments_is_redacted_before_the_upstream(env: dict[str, Any]) -> None:
    received: list[str] = []
    echo = FastMCP(name="demo-bank")

    @echo.tool(name="kb.search")
    def kb_search(query: str) -> str:
        received.append(query)
        return f"no results for {query}"

    env["mcp"].set_upstream(echo)
    res = _run(_call("kb.search", {"query": f"rotate AWS_ACCESS_KEY_ID={FAKE_AWS_KEY} please"}))
    assert not res.is_error
    assert received and FAKE_AWS_KEY not in received[0] and "[REDACTED:" in received[0]
    ev = _events(env, "mcp.call")[-1]
    assert FAKE_AWS_KEY not in json.dumps(ev)
    assert any(f["control"] == "secrets" and f["direction"] == "tool_call" for f in ev["findings"])


def test_call_outside_principal_allowlist_is_blocked(env: dict[str, Any]) -> None:
    args = {"to": "ops@bank.example", "subject": "Fees", "body": "Table attached."}
    res = _run(_call("mail.send", args, key=INTERN))
    assert res.is_error
    assert _bouncer(res)["code"] == "tool_governance.unknown_tool"
    assert "intern-bot" in _text(res)
    assert demo_tools.OUTBOX == []  # the upstream tool never ran
    ev = _events(env, "mcp.call")[-1]
    assert ev["principal"]["id"] == "intern-bot" and ev["action"] == "block" and ev["status_code"] == 403
    # the same call from a principal that may send mail goes through
    ok = _run(_call("mail.send", args, key=OPS))
    assert not ok.is_error and len(demo_tools.OUTBOX) == 1


def test_unknown_or_missing_key_is_refused(env: dict[str, Any]) -> None:
    for key in ("bk_not_a_key", None):
        with pytest.raises(Exception):  # noqa: B017 - the client surfaces the HTTP 401 as an error
            _run(_list(key))  # type: ignore[arg-type]
    r = httpx.post(env["url"] + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"Accept": "application/json, text/event-stream"}, timeout=5)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "auth.invalid_key"
    assert "Bearer" in r.headers["www-authenticate"]
    evs = _events(env)
    assert evs and all(e["findings"][0]["id"] == "auth.invalid_key" for e in evs)
    assert evs[-1]["route"] == "mcp.list"
    assert env["gw"].store.mcp_pins.get("demo-bank") in (None, {})


def test_server_not_in_allowlist_is_refused(env: dict[str, Any]) -> None:
    _set_policy(env, "servers_allow: [demo-bank]", "servers_allow: [core-banking]")
    with pytest.raises(Exception) as exc:
        _run(_list())
    assert "supply_chain.mcp_server_not_allowed" in str(exc.value)
    res = _run(_call("kb.search", {"query": "fees"}))
    assert res.is_error and _bouncer(res)["code"] == "supply_chain.mcp_server_not_allowed"
    evs = [e for e in _events(env) if e["route"].startswith("mcp.")]
    assert {e["route"] for e in evs} == {"mcp.list", "mcp.call"}
    assert all(e["findings"][0]["id"] == "supply_chain.mcp_server_not_allowed" and e["action"] == "block" for e in evs)
    assert env["gw"].store.mcp_pins.get("demo-bank") in (None, {})


def test_pinning_disabled_serves_changed_definition(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    _set_policy(env, "pin_tool_definitions: true", "pin_tool_definitions: false")
    monkeypatch.setattr(ms, "POISON_DESCRIPTION", BENIGN_CHANGE)
    assert "kb.search" in _run(_list())
    ms.set_poison(True)
    assert "kb.search" in _run(_list())
    assert not env["gw"].store.mcp_pins.get("demo-bank")
    assert not _run(_call("kb.search", {"query": "fees"})).is_error
    # content scanning still applies without pinning
    monkeypatch.setattr(ms, "POISON_DESCRIPTION", POISON)
    assert "kb.search" not in _run(_list())


def test_supply_chain_disabled_skips_allowlist_and_pins(env: dict[str, Any]) -> None:
    _set_policy(env, "    servers_allow: [demo-bank]", "    servers_allow: [core-banking]")
    text = env["policy"].read_text().replace("supply_chain:                    # OWASP LLM03, Agentic ASI04", "supply_chain:                    # OWASP LLM03, Agentic ASI04\n    enabled: false", 1)
    env["policy"].write_text(text)
    assert env["gw"].policies.reload(), env["gw"].policies.last_error
    assert "kb.search" in _run(_list())
    assert not env["gw"].store.mcp_pins.get("demo-bank")


def test_lethal_trifecta_over_mcp_requires_approval(env: dict[str, Any]) -> None:
    session = "mcp-trifecta"
    assert not _run(_call("web.fetch", {"url": "https://vendor.example/pricing"}, session=session)).is_error
    assert not _run(_call("crm.lookup_customer", {"query": "C-10007"}, session=session)).is_error
    taint = env["gw"].store.session(f"ops-copilot/{session}").taint  # sessions are namespaced by agent
    assert {"untrusted", "sensitive"} <= taint
    args = {"from_account": "PL61109010140000071219812874", "to_iban": "DE89370400440532013000", "amount": 120, "currency": "EUR", "title": "Invoice 42"}
    res = _run(_call("payments.create_transfer", args, session=session))
    assert res.is_error
    b = _bouncer(res)
    assert b["code"] == "tool_governance.lethal_trifecta" and b["action"] == "require_approval" and b["approval_id"]
    assert demo_tools.TRANSFERS == []
    # a fresh session without the taint is not stopped by the trifecta
    ok = _run(_call("payments.create_transfer", args, session="mcp-clean"))
    assert not ok.is_error, _text(ok)


def test_bouncer_key_is_not_forwarded_upstream(env: dict[str, Any]) -> None:
    echo = FastMCP(name="demo-bank")

    @echo.tool(name="kb.search")
    def kb_search(query: str) -> str:
        from fastmcp.server.dependencies import get_http_headers

        return json.dumps(get_http_headers(include_all=True))

    with _Server(echo.http_app(path="/mcp")) as upstream:
        env["mcp"].set_upstream(upstream.url + "/mcp")
        res = _run(_call("kb.search", {"query": "x"}))
    assert not res.is_error, _text(res)
    seen = json.loads(_text(res))
    assert "authorization" not in {k.lower() for k in seen}
    assert OPS not in _text(res)
    assert "x-bouncer-session" not in {k.lower() for k in seen}
