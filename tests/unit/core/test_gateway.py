"""Gateway mechanics end to end (in-process, simulated upstream): streaming, hot reload through the
app, block responses, headers, guard API."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path

import httpx
import pytest

from bouncer.gateway.app import create_app
from bouncer.gateway.state import Settings
from bouncer.selftest import _stream_text
from demo.mock_upstream import MockState
from demo.mock_upstream import create_app as create_mock

KEY = "bk_test_gateway_ops"


@pytest.fixture()
def env(tmp_path: Path):  # noqa: ANN201
    os.environ["BOUNCER_KEY_OPS_COPILOT"] = KEY
    os.environ["BOUNCER_KEY_PLAYGROUND"] = "bk_test_gateway_pg"
    policy = tmp_path / "bouncer.yaml"
    shutil.copy("policy/bouncer.yaml", policy)
    mock = MockState()
    app = create_app(
        Settings(policy_path=str(policy), audit_path=str(tmp_path / "audit.jsonl"), t1="fake", judge_override="fake", watch=False),
        upstream_transport=httpx.ASGITransport(app=create_mock(mock)),
    )
    return app, mock, policy


async def _post(app, body: dict, key: str = KEY, path: str = "/v1/chat/completions") -> httpx.Response:  # noqa: ANN001
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return await c.post(path, json=body, headers={"Authorization": f"Bearer {key}", "X-Bouncer-Session": "unit"})


def test_headers_on_allowed_request(env) -> None:  # noqa: ANN001
    app, mock, _ = env
    r = asyncio.run(_post(app, {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "What are the branch hours?"}]}))
    assert r.status_code == 200
    assert r.headers["x-bouncer-action"] == "allow"
    assert r.headers["x-bouncer-trace-id"].startswith("tr_")
    assert r.headers["x-bouncer-policy-version"].startswith("sha256:")


def test_block_error_body_shape(env) -> None:  # noqa: ANN001
    app, mock, _ = env
    mock.script([{"tool_calls": [{"name": "mail__send", "arguments": {"to": "x@gmail.com", "subject": "s", "body": "b"}}]}])
    r = asyncio.run(_post(app, {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Send fees to partner"}]}))
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["type"] == "bouncer_blocked"
    assert err["code"].startswith("tool_governance.")
    assert err["trace_id"] == r.headers["x-bouncer-trace-id"]
    assert "outside" in err["message"]


def test_block_response_message_mode(env) -> None:  # noqa: ANN001
    app, mock, policy = env
    gw = app.state.gw
    policy.write_text(policy.read_text().replace("block_response: error", "block_response: message", 1))
    assert gw.policies.reload()
    mock.script([{"tool_calls": [{"name": "mail__send", "arguments": {"to": "x@gmail.com", "subject": "s", "body": "b"}}]}])
    r = asyncio.run(_post(app, {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Send fees to partner"}]}))
    assert r.status_code == 200
    assert r.headers["x-bouncer-action"] == "block"
    assert r.json()["choices"][0]["message"]["content"].startswith("[Bouncer]")


def test_hot_reload_changes_behaviour(env) -> None:  # noqa: ANN001
    app, mock, policy = env
    gw = app.state.gw
    body = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Send the fee table to the partner."}]}
    call = [{"tool_calls": [{"name": "mail__send", "arguments": {"to": "partner@vendor.example", "subject": "Fees", "body": "Table."}}]}]
    mock.script(call)
    assert asyncio.run(_post(app, body)).status_code == 403
    policy.write_text(policy.read_text().replace("to_domains_allow: [bank.example]", "to_domains_allow: [bank.example, vendor.example]", 1))
    assert gw.policies.reload()
    mock.script(call)
    r = asyncio.run(_post(app, body))
    assert r.status_code == 200, r.text


def test_invalid_policy_keeps_serving(env) -> None:  # noqa: ANN001
    app, mock, policy = env
    gw = app.state.gw
    before = gw.policies.current.version
    policy.write_text("controls: [this is not valid")
    assert gw.policies.reload() is False
    r = asyncio.run(_post(app, {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}))
    assert r.status_code == 200
    assert r.headers["x-bouncer-policy-version"] == before


def test_stream_passes_text_and_tool_calls(env) -> None:  # noqa: ANN001
    app, mock, _ = env
    mock.script([{"content": "Branches open at 9:00 and close at 17:00 on weekdays. " * 5}])
    r = asyncio.run(_post(app, {"model": "gpt-4o-mini", "stream": True, "messages": [{"role": "user", "content": "Hours?"}]}))
    text, errors = _stream_text(r.text)
    assert not errors
    assert text == "Branches open at 9:00 and close at 17:00 on weekdays. " * 5
    assert r.text.rstrip().endswith("data: [DONE]")


def test_stream_blocks_tool_call_before_agent_sees_it(env) -> None:  # noqa: ANN001
    app, mock, _ = env
    mock.script([{"tool_calls": [{"name": "mail__send", "arguments": {"to": "x@gmail.com", "subject": "s", "body": "b"}}]}])
    r = asyncio.run(_post(app, {"model": "gpt-4o-mini", "stream": True, "messages": [{"role": "user", "content": "Send fees"}]}))
    text, errors = _stream_text(r.text)
    assert errors and errors[0]["type"] == "bouncer_blocked"
    assert "mail__send" not in text.replace(json.dumps(errors[0]), "")


def test_stream_usage_requested_upstream(env) -> None:  # noqa: ANN001
    app, mock, _ = env
    asyncio.run(_post(app, {"model": "gpt-4o-mini", "stream": True, "messages": [{"role": "user", "content": "Hi"}]}))
    assert mock.requests[-1]["stream_options"]["include_usage"] is True


def test_canary_injected_into_system_prompt(env) -> None:  # noqa: ANN001
    app, mock, _ = env
    asyncio.run(_post(app, {"model": "gpt-4o-mini", "messages": [{"role": "system", "content": "You help bank staff."}, {"role": "user", "content": "Hi"}]}))
    sys_msg = mock.requests[-1]["messages"][0]["content"]
    assert sys_msg.startswith("You help bank staff.") and "bc-" in sys_msg


def test_guard_check_tool_call(env) -> None:  # noqa: ANN001
    app, _, _ = env
    r = asyncio.run(
        _post(
            app,
            {"tool_call": {"name": "payments.create_transfer", "arguments": {"from_account": "A", "to_iban": "PL61109010140000071219812874", "amount": 50000, "currency": "PLN", "title": "x"}}, "user_request": "pay invoice 50000"},
            path="/v1/guard/check",
        )
    )
    body = r.json()
    assert body["action"] in ("require_approval", "block")
    assert any(f["id"] == "tool_governance.amount_over_limit" for f in body["findings"])
    assert body["approval_id"] or body["action"] == "block"


def test_unauthorized_is_audited(env) -> None:  # noqa: ANN001
    app, _, _ = env
    r = asyncio.run(_post(app, {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hi"}]}, key="wrong"))
    assert r.status_code == 401
    ev = app.state.gw.audit.get(r.headers["x-bouncer-trace-id"])
    assert ev["findings"][0]["id"] == "auth.invalid_key"
