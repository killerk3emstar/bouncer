"""RedisStore: two store instances on one fake Redis server stand for two gateway replicas."""

from __future__ import annotations

import asyncio
import os
import shutil
import threading
import time
from pathlib import Path

import fakeredis
import httpx
import pytest

from bouncer.gateway.app import create_app
from bouncer.gateway.state import Settings, build_store
from bouncer.store import Store
from bouncer.store_redis import RedisStore, RedisUnavailable


@pytest.fixture()
def server() -> fakeredis.FakeServer:
    return fakeredis.FakeServer()


def _replica(server: fakeredis.FakeServer, prefix: str = "bouncer:") -> RedisStore:
    return RedisStore(fakeredis.FakeRedis(server=server), prefix=prefix)


@pytest.fixture()
def pair(server: fakeredis.FakeServer) -> tuple[RedisStore, RedisStore]:
    return _replica(server), _replica(server)


def _approval(store: Store, **over: object):  # noqa: ANN202
    kw = dict(
        principal="ops-copilot",
        principal_key="ops-copilot",
        team="operations",
        session_id="s1",
        call_hash="h1",
        tool="payments.create_transfer",
        arguments_masked="{}",
        reason="needs approval",
        finding_ids=["tool_governance.approval"],
        trace_id="tr_1",
        ttl_seconds=600,
    )
    kw.update(over)
    return store.create_approval(**kw)


def test_spend_on_one_replica_is_seen_by_the_other(pair) -> None:  # noqa: ANN001
    a, b = pair
    a.add_spend("operations", "s1", 1.25, 1000, 2.5)
    b.add_spend("operations", "s1", 0.75, 500, 0.0)
    assert a.team_spend_today("operations") == pytest.approx(2.0)
    assert b.team_spend_today("operations") == pytest.approx(2.0)
    assert b.team_spend_today("engineering") == 0.0
    assert a.team_requests.get("operations", 0) == 2
    assert b.team_requests.get("engineering", 0) == 0
    assert b.session("s1").usd == pytest.approx(2.0)
    assert b.gpu_seconds_last_hour("operations") == pytest.approx(2.5)
    ttl = a.r.ttl("bouncer:usd:operations:" + time.strftime("%Y-%m-%d", time.gmtime()))
    assert 0 < ttl <= 2 * 24 * 3600


def test_tokens_window_counts_only_the_last_minute(pair) -> None:  # noqa: ANN001
    a, b = pair
    a.add_spend("eng", "s", 0.0, 300, 0.0)
    b.add_spend("eng", "s", 0.0, 200, 0.0)
    assert a.tokens_last_minute("eng") == 500
    old = time.time() - 61
    a.r.zadd("bouncer:tokens:eng", {f"{old}:9999:x": old})
    assert b.tokens_last_minute("eng") == 500  # the old entry is outside the window and trimmed
    assert a.r.zcard("bouncer:tokens:eng") == 2


def test_replay_spend_is_a_noop(pair) -> None:  # noqa: ANN001
    a, _ = pair
    ev = {"type": "decision", "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()), "principal": {"team": "t"}, "usage": {"cost_usd": 3}}
    assert a.replay_spend([ev]) == 0
    assert a.team_spend_today("t") == 0.0


def test_session_taint_steps_and_breaker_are_shared(pair) -> None:  # noqa: ANN001
    a, b = pair
    a.mark_taint("s1", "untrusted", "web.fetch")
    b.mark_taint("s1", "untrusted", "web.fetch")  # same source once
    b.mark_taint("s1", "sensitive", "crm.lookup")
    s = a.session("s1")
    assert s.taint == {"untrusted", "sensitive"}
    assert s.taint_sources == {"untrusted": ["web.fetch"], "sensitive": ["crm.lookup"]}
    assert s.taint_sources.get("other", []) == []

    a.session("s1").steps += 1
    b.session("s1").steps += 1
    sa, sb = a.session("s1"), b.session("s1")
    sa.steps += 1
    sb.steps += 1  # stale snapshot on b: still counted, written as an increment
    assert a.session("s1").steps == 4

    sb.breaker_until = time.time() + 60
    sb.breaker_reason = "kb.search repeated 4 times"
    s = a.session("s1")
    assert s.breaker_until > time.time()
    assert s.breaker_reason == "kb.search repeated 4 times"
    assert a.session("other").steps == 0 and a.session("other").taint == set()
    with pytest.raises(AttributeError):
        s.taint_count = 1  # type: ignore[attr-defined]
    assert 0 < a.r.ttl("bouncer:sess:s1") <= 24 * 3600


def test_session_steps_increments_are_not_lost_under_threads(pair) -> None:  # noqa: ANN001
    a, b = pair

    def work(st: RedisStore) -> None:
        for _ in range(25):
            st.session("s").steps += 1

    ts = [threading.Thread(target=work, args=(st,)) for st in (a, b, a, b)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert a.session("s").steps == 100


def test_loop_detection_count_is_shared(pair) -> None:  # noqa: ANN001
    a, b = pair
    a.record_tool_call("s1", "hX")
    b.record_tool_call("s1", "hX")
    a.record_tool_call("s1", "hY")
    assert b.identical_calls("s1", "hX", 120) == 2
    assert a.identical_calls("s1", "hY", 120) == 1
    assert a.identical_calls("s2", "hX", 120) == 0
    assert [h for _, h in b.session("s1").tool_calls] == ["hX", "hX", "hY"]
    for _ in range(250):
        a.record_tool_call("s1", "hZ")
    assert a.r.zcard("bouncer:sess:s1:calls") == 200


def test_approval_approved_on_a_is_consumed_once_on_b(pair) -> None:  # noqa: ANN001
    a, b = pair
    appr = _approval(a)
    assert _approval(b).id == appr.id  # one pending request per identical call, across replicas
    assert [x.id for x in b.list_approvals("pending")] == [appr.id]
    assert b.approved("ops-copilot", "h1", "s1") is None  # still pending
    decided = a.decide_approval(appr.id, "approve", "ok", 300)
    assert decided is not None and decided.status == "approved" and decided.allow_until
    assert b.decide_approval(appr.id, "deny", None, 300).status == "approved"  # already decided
    assert b.approved("ops-copilot", "h1", "other-session") is None
    used = b.approved("ops-copilot", "h1", "s1")
    assert used is not None and used.id == appr.id
    assert a.approved("ops-copilot", "h1", "s1") is None
    assert b.approved("ops-copilot", "h1", "s1") is None
    assert a.approvals[appr.id].status == "used"
    assert appr.id in a.approvals and len(b.approvals) == 1


def test_concurrent_consumers_get_one_approval(server) -> None:  # noqa: ANN001
    stores = [_replica(server) for _ in range(6)]
    appr = _approval(stores[0])
    stores[1].decide_approval(appr.id, "approve", None, 300)
    wins: list[object] = []
    barrier = threading.Barrier(len(stores))

    def take(st: RedisStore) -> None:
        barrier.wait()
        r = st.approved("ops-copilot", "h1", "s1")
        if r is not None:
            wins.append(r)

    ts = [threading.Thread(target=take, args=(st,)) for st in stores]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(wins) == 1


def test_expired_approval(pair) -> None:  # noqa: ANN001
    a, b = pair
    appr = _approval(a, ttl_seconds=-1)
    assert [x.status for x in b.list_approvals()] == ["expired"]
    assert a.approvals[appr.id].status == "expired"
    assert a.decide_approval(appr.id, "approve", None, 300).status == "expired"
    assert b.approved("ops-copilot", "h1", "s1") is None
    assert a.decide_approval("apr_missing", "approve", None, 300) is None
    # an approval whose window passed is not consumed
    appr2 = _approval(a, call_hash="h2")
    a.decide_approval(appr2.id, "approve", None, -1)
    assert b.approved("ops-copilot", "h2", "s1") is None


def test_mcp_pins_are_shared(pair) -> None:  # noqa: ANN001
    a, b = pair
    assert a.mcp_pins.get("demo-bank") is None
    assert not b.mcp_pins.get("demo-bank")
    pins = a.mcp_pins["demo-bank"]
    assert pins.get("kb.search") is None
    pins["kb.search"] = "sha256:aaa"
    b.mcp_pending["demo-bank"]["kb.search"] = "sha256:bbb"
    assert b.mcp_pins["demo-bank"]["kb.search"] == "sha256:aaa"
    assert {s: dict(p) for s, p in b.mcp_pins.items()} == {"demo-bank": {"kb.search": "sha256:aaa"}}
    assert a.mcp_pending["demo-bank"].pop("kb.search", None) == "sha256:bbb"
    assert dict(b.mcp_pending.items()) == {}
    assert "demo-bank" in b.mcp_pins and "x" not in b.mcp_pins


def test_scan_cache_is_local_and_prefix_isolates_deployments(server) -> None:  # noqa: ANN001
    a, b = _replica(server), _replica(server)
    a.cache_put(("k",), 1)
    assert a.cache_get(("k",)) == 1 and b.cache_get(("k",)) is None
    c = _replica(server, prefix="other:")
    a.add_spend("t", "s", 1.0, 1, 0.0)
    assert c.team_spend_today("t") == 0.0
    c.reset()
    assert a.team_spend_today("t") == 1.0
    a.reset()
    assert b.team_spend_today("t") == 0.0


def test_store_selection_and_unreachable_redis() -> None:
    assert type(build_store(Settings())) is Store
    with pytest.raises(RedisUnavailable, match="not reachable"):
        build_store(Settings(store="unix:///nonexistent/bouncer-test.sock"))
    with pytest.raises(ValueError):
        build_store(Settings(store="postgres://x"))


def test_settings_from_env(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("BOUNCER_ADMIN_TOKEN", "adm_x")
    monkeypatch.delenv("BOUNCER_STORE", raising=False)
    assert Settings.from_env().store == "memory"
    monkeypatch.setenv("BOUNCER_STORE", "redis://127.0.0.1:6390/0")
    monkeypatch.setenv("BOUNCER_STORE_PREFIX", "bank1:")
    s = Settings.from_env()
    assert s.store == "redis://127.0.0.1:6390/0" and s.store_prefix == "bank1:"


# ---------------------------------------------------------------- two gateway replicas, one Redis
KEY = "bk_test_redis_ops"
ADMIN = "adm_test_redis"
TRANSFER = {"name": "payments__create_transfer", "arguments": {"from_account": "A", "to_iban": "PL61109010140000071219812874", "amount": 5000, "currency": "PLN", "title": "x"}}


@pytest.fixture()
def replicas(tmp_path: Path, server: fakeredis.FakeServer):  # noqa: ANN201
    from demo.mock_upstream import MockState
    from demo.mock_upstream import create_app as create_mock

    os.environ["BOUNCER_KEY_OPS_COPILOT"] = KEY
    out = []
    for name in ("a", "b"):
        d = tmp_path / name
        d.mkdir()
        policy = d / "bouncer.yaml"
        shutil.copy("policy/bouncer.yaml", policy)
        mock = MockState()
        app = create_app(
            Settings(policy_path=str(policy), audit_path=str(d / "audit.jsonl"), t1="fake", judge_override="fake", watch=False, admin_token=ADMIN),
            upstream_transport=httpx.ASGITransport(app=create_mock(mock)),
            store=_replica(server),
        )
        out.append((app, mock))
    return out


async def _req(app, method: str, path: str, body: dict | None = None, key: str = KEY) -> httpx.Response:  # noqa: ANN001
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        headers = {"Authorization": f"Bearer {key}", "X-Bouncer-Session": "redis-unit"}
        return await c.request(method, path, json=body, headers=headers)


def _chat(app, content: str) -> httpx.Response:  # noqa: ANN001
    return asyncio.run(_req(app, "POST", "/v1/chat/completions", {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": content}]}))


def test_gateway_budget_spent_on_a_downgrades_on_b(replicas) -> None:  # noqa: ANN001
    (app_a, _), (app_b, mock_b) = replicas
    assert isinstance(app_a.state.gw.store, RedisStore)
    r = _chat(app_a, "What are the branch hours?")
    assert r.status_code == 200
    spent = app_a.state.gw.store.team_spend_today("operations")
    assert spent > 0
    budgets = asyncio.run(_req(app_b, "GET", "/api/budgets", key=ADMIN)).json()
    ops = next(t for t in budgets["teams"] if t["team"] == "operations")
    assert ops["spent_usd"] == pytest.approx(spent, abs=1e-6) and ops["requests"] == 1
    assert app_b.state.gw.store.session("ops-copilot/redis-unit").steps == 1
    app_a.state.gw.store.add_spend("operations", "elsewhere", 10.0, 0, 0.0)  # the daily 5 USD is gone
    r = _chat(app_b, "Draft a reply about card delivery times.")
    assert r.status_code == 200
    assert mock_b.requests[-1].get("model") == "qwen3:8b"


def test_gateway_approval_on_a_used_once_on_b(replicas) -> None:  # noqa: ANN001
    (app_a, mock_a), (app_b, mock_b) = replicas
    mock_a.script([{"tool_calls": [TRANSFER]}])
    r = _chat(app_a, "Pay invoice 5000 PLN")
    assert r.status_code == 403
    appr = r.json()["error"]["approval_id"]
    listed = asyncio.run(_req(app_b, "GET", "/api/approvals?status=pending", key=ADMIN)).json()["approvals"]
    assert [x["id"] for x in listed] == [appr]
    assert asyncio.run(_req(app_b, "POST", f"/api/approvals/{appr}", {"decision": "approve"}, key=ADMIN)).status_code == 200
    assert asyncio.run(_req(app_a, "POST", f"/api/approvals/{appr}", {"decision": "deny"}, key=ADMIN)).status_code == 409
    mock_b.script([{"tool_calls": [TRANSFER]}])
    r = _chat(app_b, "Pay invoice 5000 PLN")
    assert r.status_code == 200, r.text
    assert asyncio.run(_req(app_a, "GET", f"/v1/approvals/{appr}")).json()["status"] == "used"
    mock_a.script([{"tool_calls": [TRANSFER]}])
    r = _chat(app_a, "Pay invoice 5000 PLN")
    assert r.status_code == 403  # consumed: the same call needs a new approval
