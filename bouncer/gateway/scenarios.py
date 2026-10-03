"""Run a scripted demo scenario (demo/scenarios/*.yaml) in-process for the dashboard.

The scripted model responses are pushed to the simulated upstream (/mock/script), then the
Bank Ops Copilot tool loop runs through the real gateway pipeline: every model call is checked,
tools run locally on fake data (demo/tools.py), and the run stops at the first block.
"""

from __future__ import annotations

import copy
import fnmatch
import json
import time
from typing import Any

from bouncer.audit import now_iso
from bouncer.gateway.openai_proxy import handle_chat

DEFAULT_SYSTEM = (
    "You are Bank Ops Copilot, an assistant for operations staff at a bank. Use the tools to look up "
    "customers, search the knowledge base, fetch web pages, send e-mail and create transfers."
)


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


async def run_scenario_file(g: Any, sc: dict[str, Any]) -> dict[str, Any]:
    from demo.tools import openai_tools, reset_state, run_tool

    sid = sc["id"]
    started = time.perf_counter()
    expect = sc.get("expect") or {}
    out: dict[str, Any] = {
        "scenario": sid,
        "title": sc.get("title"),
        "mode": "scripted",
        "started_at": now_iso(),
        "expected_action": expect.get("outcome"),
        "steps": [],
    }
    if sc.get("kind", "openai") == "mcp":
        return await _run_mcp(g, sc, out, started)
    if sc.get("kind", "openai") != "openai":
        out.update({"final_action": None, "passed": None, "duration_ms": 0, "note": f"scenario kind {sc.get('kind')} is not supported here"})
        return out
    policy = g.policies.current
    principal = policy.principal(sc["principal"])
    if principal is None:
        out.update({"final_action": None, "passed": False, "note": f"principal {sc['principal']} is not in the active policy"})
        return out
    model = sc.get("model") or principal.models[0]
    mcfg = policy.doc.models.get(model)
    if mcfg is None:
        out.update({"final_action": None, "passed": False, "note": f"model {model} is not in the active policy"})
        return out
    base = policy.doc.upstreams[mcfg.upstream].base_url
    mock_root = base[:-3] if base.endswith("/v1") else base
    client = g.client_for(mock_root)
    await client.post("/mock/script", json={"responses": sc.get("responses") or [], "replace": True})
    reset_state()

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": sc.get("system") or DEFAULT_SYSTEM},
        {"role": "user", "content": sc["user"]},
    ]
    tools = openai_tools(sc.get("tools"))
    session = f"scn_{sid}_{int(time.time() * 1000)}"
    step_expect = {s.get("step"): s for s in expect.get("steps") or []}
    outcome = "completed"
    code = None
    downgraded = False
    n_calls = len(sc.get("responses") or []) + 1
    for n in range(1, n_calls + 1):
        body = {"model": model, "messages": copy.deepcopy(messages), "tools": tools}
        resp = await handle_chat(g, principal, body, session)
        trace_id = resp.headers.get("x-bouncer-trace-id")
        ev = g.audit.get(trace_id) if trace_id else None
        payload = json.loads(resp.body)
        action = (ev or {}).get("action") or resp.headers.get("x-bouncer-action")
        downgraded = downgraded or bool((ev or {}).get("downgraded_from"))
        exp = step_expect.get(n) or {}
        exp_actions = _as_list(exp.get("action"))
        ok = not exp_actions or action in exp_actions
        fids = [f.get("id", "") for f in (ev or {}).get("findings", [])]
        for pat in _as_list(exp.get("findings")):
            ok = ok and any(fnmatch.fnmatch(f, pat) for f in fids)
        if exp.get("findings_any"):
            ok = ok and any(fnmatch.fnmatch(f, pat) for pat in exp["findings_any"] for f in fids)
        step = {"n": n, "trace_id": trace_id, "action": action, "expected_action": exp_actions[0] if len(exp_actions) == 1 else (exp_actions or None), "ok": ok, "events": [ev] if ev else []}
        out["steps"].append(step)
        if resp.status_code != 200 or "error" in payload:
            err = payload.get("error") or {}
            code = err.get("code")
            outcome = "approval_required" if err.get("approval_id") else "blocked"
            step["title"] = f"Model call {n}: stopped by Bouncer ({code})"
            step["message"] = err.get("message")
            break
        msg = (payload.get("choices") or [{}])[0].get("message") or {}
        if msg.get("content", "").startswith("[Bouncer]") if isinstance(msg.get("content"), str) else False:
            outcome = "blocked"
            step["title"] = f"Model call {n}: stopped by Bouncer"
            break
        assistant = {"role": "assistant", "content": msg.get("content")}
        if msg.get("tool_calls"):
            assistant["tool_calls"] = msg["tool_calls"]
        messages.append(assistant)
        if msg.get("tool_calls"):
            names = []
            for tc in msg["tool_calls"]:
                fn = tc.get("function") or {}
                names.append(fn.get("name", ""))
                result = run_tool(fn.get("name", ""), fn.get("arguments"))
                messages.append({"role": "tool", "tool_call_id": tc.get("id"), "content": result})
            step["title"] = f"Model call {n}: tool call {', '.join(names)}"
            continue
        step["title"] = f"Model call {n}: final answer"
        out["answer"] = msg.get("content")
        break
    if downgraded and outcome == "completed":
        outcome = "downgraded"
    expected = _as_list(expect.get("outcome"))
    passed = (not expected or outcome in expected or (downgraded and "downgraded" in expected)) and all(s["ok"] for s in out["steps"])
    if code and expect.get("code"):
        passed = passed and any(fnmatch.fnmatch(code, pat) for pat in _as_list(expect["code"]))
    out.update(
        {
            "final_action": out["steps"][-1]["action"] if out["steps"] else None,
            "outcome": outcome,
            "code": code,
            "passed": passed,
            "duration_ms": round((time.perf_counter() - started) * 1000),
        }
    )
    return out


async def _run_mcp(g: Any, sc: dict[str, Any], out: dict[str, Any], started: float) -> dict[str, Any]:
    """Drive the MCP steps through this gateway's own /mcp endpoint, as an MCP client would."""
    import os

    from demo.agent import McpUnavailable, _mcp_steps

    policy = g.policies.current
    key = next((k for k, pid in policy.keys.items() if pid == sc["principal"]), None)
    if key is None:
        out.update({"final_action": None, "passed": False, "note": f"no API key configured for {sc['principal']}"})
        return out
    port = os.environ.get("BOUNCER_PORT", "8700")
    admin_url = os.environ.get("DEMO_MCP_ADMIN_URL", "http://127.0.0.1:8703")
    session = f"scn_{sc['id']}_{int(time.time() * 1000)}"
    try:
        res = await _mcp_steps(sc, f"http://127.0.0.1:{port}/mcp", admin_url, key, session, False)
    except McpUnavailable as exc:
        out.update({"final_action": None, "passed": None, "duration_ms": round((time.perf_counter() - started) * 1000), "note": str(exc)})
        return out
    for st in res.steps:
        ev = g.audit.get(st.trace_id) if st.trace_id else None
        out["steps"].append(
            {
                "n": st.index,
                "title": f"MCP step {st.index}: {st.detail}"[:160],
                "trace_id": st.trace_id,
                "action": (ev or {}).get("action") or st.action,
                "expected_action": None,
                "ok": True,
                "events": [ev] if ev else [],
            }
        )
    expect = sc.get("expect") or {}
    expected = _as_list(expect.get("outcome"))
    passed = not expected or res.outcome in expected
    if res.block_code and expect.get("code"):
        passed = passed and any(fnmatch.fnmatch(res.block_code, pat) for pat in _as_list(expect["code"]))
    out.update(
        {
            "final_action": out["steps"][-1]["action"] if out["steps"] else None,
            "outcome": res.outcome,
            "code": res.block_code,
            "passed": passed,
            "duration_ms": round((time.perf_counter() - started) * 1000),
        }
    )
    return out
