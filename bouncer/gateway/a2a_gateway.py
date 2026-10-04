"""A2A gateway: Bouncer between two agents that speak the Agent2Agent (A2A) protocol.

Endpoints (gateway port):
- POST /a2a/{agent_id}: JSON-RPC 2.0, method message/send (alias tasks/send). The calling agent
  authenticates with its own Bouncer key (Authorization: Bearer <key>); X-Bouncer-On-Behalf-Of works as on
  the other routes. The key is never forwarded to the target agent.
- GET /a2a/{agent_id}/.well-known/agent.json: the target's agent card, checked like a tool definition, with
  its url rewritten to the Bouncer route so that clients keep calling through the gateway.

What is enforced (policy section a2a, the text controls):
- Agent allowlist: only agents listed in a2a.agents can be called, and only by the principals in
  a2a.agents.<id>.allowed_callers (with delegation, both the caller and the agent it acts for must be listed).
  Otherwise auth.a2a_not_allowed (403).
- Inbound: text parts and JSON-serialized data parts of the caller's message go through the input pipeline
  as a user message from another agent: secrets and PII redaction (the redacted text is what the target
  receives), obfuscation, injection heuristics, signatures, harmful requests, T1 classifier and T2 judge,
  budgets and the session step limit. File parts and message metadata are not checked, so they are not
  forwarded.
- Outbound: text and data parts of the target's reply (Message, or Task status message, artifacts and
  history) are scanned as an untrusted tool result (secrets, PII, injection aimed at the caller, signatures,
  T1/T2) plus the output checks (markdown image/link exfiltration, HTML). Redacted or withheld; the reply
  marks the caller's session as untrusted for the lethal trifecta check.
- Size: a message or reply longer than a2a.max_message_chars is refused.

Each call writes one audit event per direction (route a2a.send): direction input for the caller's message
(written before the target is called) and direction output for the reply; the output event carries the
request event's trace id in a2a.request_trace_id. Blocks are JSON-RPC errors with code -32001 and the
Bouncer message, rule and trace id in error.data.bouncer. Messages are not signed end to end.
"""

from __future__ import annotations

import copy
import json
import os
import time
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from bouncer.core import Action, Finding, Principal, Segment
from bouncer.gateway.openai_proxy import (
    authenticate,
    bouncer_headers,
    delegation,
    error_body,
    gw,
    unauthorized,
)
from bouncer.pipeline import RequestCtx, apply_redactions

router = APIRouter()

ROUTE = "a2a.send"
CARD_ROUTE = "a2a.card"
METHODS = ("message/send", "tasks/send")

BLOCKED = -32001  # Bouncer policy decision (same code as the MCP gateway)
UPSTREAM_ERROR = -32002  # the target agent could not be reached or answered with something that is not A2A
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
PARSE_ERROR = -32700


# ---------------------------------------------------------------------- helpers
def rpc_error(rpc_id: Any, code: int, message: str, status: int, bouncer: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> JSONResponse:
    err: dict[str, Any] = {"code": code, "message": message}
    if bouncer is not None:
        err["data"] = {"bouncer": bouncer}
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": err}, status_code=status, headers=headers or {})


def _from_plain(resp: JSONResponse, rpc_id: Any) -> JSONResponse:
    """Turn a Bouncer error response of the shared auth helpers into a JSON-RPC error (same status and headers)."""
    e = (json.loads(bytes(resp.body)) or {}).get("error") or {}
    trace = e.get("trace_id")
    headers = {k: v for k, v in resp.headers.items() if k.lower().startswith("x-bouncer")}
    msg = f"[Bouncer] {e.get('message')} (rule {e.get('code')}, trace {trace})"
    return rpc_error(rpc_id, BLOCKED, msg, resp.status_code, {"action": "block", "code": e.get("code"), "message": e.get("message"), "trace_id": trace}, headers)


def _rpc_block(ctx: RequestCtx, action: Action, code: str | None, message: str, rpc_id: Any, extra_headers: dict[str, str] | None = None) -> JSONResponse:
    parts = [f"rule {code}"] if code else []
    parts.append(f"trace {ctx.trace_id}")
    if ctx.approval_id:
        parts.append(f"approval {ctx.approval_id}")
    data = {
        "action": action.label,
        "code": code,
        "message": message,
        "trace_id": ctx.trace_id,
        "approval_id": ctx.approval_id,
        "policy_version": ctx.policy.version,
    }
    headers = {**bouncer_headers(ctx, action, ctx.policy.version), **(extra_headers or {})}
    return rpc_error(rpc_id, BLOCKED, f"[Bouncer] {message} ({', '.join(parts)})", ctx.status_code or 403, data, headers)


def _agent_findings(g: Any, ctx: RequestCtx, agent_id: str) -> list[Finding]:
    """a2a.agents allowlist and allowed_callers. Empty list = the call may go ahead."""
    cfg = ctx.doc.a2a
    agent = cfg.agents.get(agent_id) if cfg.enabled else None
    if not cfg.enabled:
        msg = "The A2A gateway is turned off in the policy (a2a.enabled: false). Turn it on to route agent-to-agent messages through Bouncer."
    elif agent is None:
        known = ", ".join(sorted(cfg.agents)) or "none"
        msg = (
            f"Agent '{agent_id[:64]}' is not in the policy (a2a.agents; known: {known}), so Bouncer does not forward "
            "messages to it. Add the agent with its URL and allowed_callers after a review, or call a listed agent."
        )
    else:
        callers = [ctx.principal.id] + ([ctx.principal.via] if ctx.principal.via else [])
        denied = [c for c in callers if c not in agent.allowed_callers]
        if not denied:
            return []
        msg = (
            f"{denied[0]} may not send messages to agent '{agent_id}' (a2a.agents.{agent_id}.allowed_callers: "
            f"{', '.join(agent.allowed_callers) or 'empty'}). Ask the policy owner to add the caller if this agent "
            "is meant to talk to the other one."
        )
    f = g.engine._finding("auth", "a2a_not_allowed", Action.BLOCK, msg, severity="high", owasp_agentic=["ASI07", "ASI03"], evidence=f"agent={agent_id[:64]}")
    f.direction, f.source = "input", f"a2a:{agent_id[:64]}"
    return [f]


def _size_finding(g: Any, ctx: RequestCtx, chars: int, limit: int, what: str, direction: str) -> Finding:
    f = g.engine._finding(
        "budgets",
        "a2a_message_chars",
        Action.BLOCK,
        f"The {what} has {chars} characters of text (limit a2a.max_message_chars = {limit}). Split it into "
        "smaller messages or raise the limit.",
        severity="low",
    )
    f.direction = direction
    return f


def agent_url(agent_id: str, agent: Any) -> str:
    """Policy URL, or BOUNCER_A2A_URL_<AGENT_ID> (upper case, - as _) when set (e.g. inside docker)."""
    return os.environ.get("BOUNCER_A2A_URL_" + agent_id.upper().replace("-", "_").replace(".", "_")) or agent.url


def card_url(agent_id: str, agent: Any) -> str:
    if agent.card_url:
        return agent.card_url
    parts = urlsplit(agent_url(agent_id, agent))
    return f"{parts.scheme}://{parts.netloc}/.well-known/agent.json"


def _client(g: Any, timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=g.a2a_transport, timeout=httpx.Timeout(timeout, connect=5.0))


def _kind(part: Any) -> str:
    if not isinstance(part, dict):
        return "invalid"
    return str(part.get("kind") or part.get("type") or ("text" if "text" in part else "data" if "data" in part else "unknown"))


def _part_text(part: dict[str, Any]) -> str | None:
    kind = _kind(part)
    if kind == "text" and isinstance(part.get("text"), str):
        return part["text"]
    if kind == "data" and "data" in part:
        return json.dumps(part["data"], ensure_ascii=False)
    return None


def _with_text(part: dict[str, Any], text: str) -> dict[str, Any]:
    """The part with its (redacted) text written back; a data part that no longer parses becomes a text part."""
    if _kind(part) == "text":
        return {**part, "text": text}
    try:
        return {**part, "data": json.loads(text)}
    except json.JSONDecodeError:
        return {"kind": "text", "text": text}


def _withheld(part: Any, who: str) -> dict[str, Any]:
    return {"kind": "text", "text": f"[Bouncer: {_kind(part)} part from {who} withheld; only text and data parts are checked and forwarded]"}


def _parts_lists(obj: Any, out: list[list[Any]]) -> list[list[Any]]:
    """Every `parts` list in an A2A result (Message, Task status message, artifacts, history)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "parts" and isinstance(v, list):
                out.append(v)
            else:
                _parts_lists(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _parts_lists(v, out)
    return out


def _drop_metadata(obj: Any) -> Any:
    """metadata fields are free-form and not checked, so they are not passed on."""
    if isinstance(obj, dict):
        return {k: _drop_metadata(v) for k, v in obj.items() if k != "metadata"}
    if isinstance(obj, list):
        return [_drop_metadata(v) for v in obj]
    return obj


def _string_leaves(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _string_leaves(v)]
    if isinstance(value, list):
        return [s for v in value for s in _string_leaves(v)]
    return []


def _upstream_finding(g: Any, agent_id: str, detail: str) -> Finding:
    f = g.engine._finding("gateway", "upstream_error", Action.LOG, f"Call to agent {agent_id} failed: {detail}. Check that the agent is running at the URL in a2a.agents.{agent_id}.url.", severity="low")
    f.effective_action = Action.LOG
    return f


# ---------------------------------------------------------------------- message/send
@router.post("/a2a/{agent_id}")
async def a2a_send(request: Request, agent_id: str) -> Any:
    g = gw(request)
    raw = await request.body()
    try:
        body: Any = json.loads(raw)
        parsed = True
    except (json.JSONDecodeError, UnicodeDecodeError):
        body, parsed = None, False
    rpc_id = body.get("id") if isinstance(body, dict) else None
    principal = authenticate(g, request)
    if principal is None:
        return _from_plain(unauthorized(g, ROUTE), rpc_id)
    principal, denied = delegation(g, request, principal, ROUTE)
    if denied is not None:
        return _from_plain(denied, rpc_id)
    if not parsed:
        return rpc_error(None, PARSE_ERROR, "Request body is not valid JSON.", 400)
    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or not isinstance(body.get("method"), str):
        return rpc_error(rpc_id, INVALID_REQUEST, "Body must be a JSON-RPC 2.0 request object with jsonrpc: \"2.0\", method, params and id.", 400)
    if body["method"] not in METHODS:
        return rpc_error(
            rpc_id,
            METHOD_NOT_FOUND,
            f"Method {body['method'][:64]} is not proxied by Bouncer. Supported: message/send (alias tasks/send); "
            "streaming and task management methods are not checked yet, so they are refused.",
            400,
        )
    params = body.get("params")
    message = params.get("message") if isinstance(params, dict) else None
    if not isinstance(message, dict) or not isinstance(message.get("parts"), list) or not message["parts"]:
        return rpc_error(rpc_id, INVALID_PARAMS, "params.message must be an object with a non-empty parts list.", 400)
    sid = request.headers.get("x-bouncer-session") or message.get("contextId") or f"a2a_{agent_id}"
    return await handle_send(g, principal, agent_id, body, str(sid)[:128], request.headers.get("x-bouncer-user-request"))


async def handle_send(g: Any, principal: Principal, agent_id: str, body: dict[str, Any], session_id: str, user_request: str | None = None) -> JSONResponse:
    """Shared by the HTTP route and the tests: inbound check, forward, outbound check."""
    engine = g.engine
    rpc_id = body.get("id")
    params = body["params"]
    message = params["message"]
    ctx = engine.begin(principal, ROUTE, session_id, None)
    ctx.direction = "input"
    info: dict[str, Any] = {"agent": agent_id[:64], "method": body["method"]}

    # 1. who may talk to whom
    deny = _agent_findings(g, ctx, agent_id)
    if deny:
        return _block_now(g, ctx, deny, rpc_id, info)
    doc = ctx.doc
    acfg = doc.a2a
    agent = acfg.agents[agent_id]

    # 2. the caller's message: every text and data part is one user message from another agent
    parts = list(message["parts"])
    slots: dict[int, int] = {}
    texts: list[str] = []
    for i, p in enumerate(parts):
        t = _part_text(p) if isinstance(p, dict) else None
        if t is not None:
            slots[i] = len(texts)
            texts.append(t)
    withheld = [i for i in range(len(parts)) if i not in slots]
    if withheld:
        ctx.notes.append(f"{len(withheld)} non-text part(s) of the message withheld (not checked)")
    if isinstance(message.get("metadata"), dict) or isinstance(params.get("metadata"), dict):
        ctx.notes.append("message metadata not forwarded (not checked)")
    chars = sum(len(t) for t in texts)
    if chars > acfg.max_message_chars:
        return _block_now(g, ctx, [_size_finding(g, ctx, chars, acfg.max_message_chars, f"message to agent {agent_id}", "input")], rpc_id, info)
    req_body: dict[str, Any] = {"messages": [{"role": "user", "content": t} for t in texts]}
    ctx.scan.extra["body"] = req_body
    decision = await engine.inspect_input(ctx, req_body)
    if user_request:
        ctx.user_request = user_request
    ctx.excerpt = f"to {agent_id}: {ctx.excerpt}"[: doc.audit.excerpt_chars]
    if decision.blocked:
        engine.finish(ctx, decision.action, direction="input", extra={"a2a": info})
        return _rpc_block(ctx, decision.action, decision.code, f"Message to agent {agent_id} blocked. {decision.message}", rpc_id)
    in_action = decision.action

    new_parts = []
    for i, p in enumerate(parts):
        if i in slots:
            new_parts.append(_with_text(p, req_body["messages"][slots[i]]["content"]))
        else:
            new_parts.append(_withheld(p, principal.id))
    fwd_msg = {k: v for k, v in message.items() if k != "metadata"}
    fwd_msg["parts"] = new_parts
    fwd_params: dict[str, Any] = {"message": fwd_msg}
    if isinstance(params.get("configuration"), dict):
        fwd_params["configuration"] = params["configuration"]
    fwd = {"jsonrpc": "2.0", "id": rpc_id, "method": body["method"], "params": fwd_params}

    # the reply gets its own event; the request event is written now, before the target sees anything
    out = engine.begin(principal, ROUTE, ctx.session_id, None)
    out.direction = "output"
    out.user_request = ctx.user_request
    info_in = {**info, "reply_trace_id": out.trace_id, "parts": len(parts), "withheld_parts": len(withheld)}
    engine.finish(ctx, in_action, direction="input", extra={"a2a": info_in}, status_code=200)
    info_out = {**info, "request_trace_id": ctx.trace_id}
    link = {"X-Bouncer-Request-Trace-Id": ctx.trace_id}

    # 3. forward
    url = agent_url(agent_id, agent)
    t = time.perf_counter()
    try:
        async with _client(g, acfg.timeout_seconds) as client:
            resp = await client.post(url, json=fwd, headers={"content-type": "application/json", "x-bouncer-caller": principal.id, "x-bouncer-trace-id": ctx.trace_id})
        reply = resp.json()
        if not isinstance(reply, dict) or ("result" not in reply and "error" not in reply):
            raise ValueError(f"HTTP {resp.status_code}, not a JSON-RPC response")
    except (httpx.HTTPError, ValueError) as exc:
        out.latency["upstream"] = (time.perf_counter() - t) * 1000
        detail = f"{type(exc).__name__}: {exc}"[:300]
        out.findings.append(_upstream_finding(g, agent_id, detail))
        engine.finish(out, in_action, direction="output", extra={"a2a": info_out, "upstream_error": detail}, status_code=502, message=f"Call to agent {agent_id} failed: {detail[:200]}")
        return rpc_error(
            rpc_id,
            UPSTREAM_ERROR,
            f"[Bouncer] Call to agent {agent_id} failed: {detail}. Check that the agent is running (a2a.agents.{agent_id}.url). (trace {out.trace_id})",
            502,
            {"action": in_action.label, "code": "gateway.upstream_error", "trace_id": out.trace_id, "request_trace_id": ctx.trace_id},
            {**bouncer_headers(out, in_action, out.policy.version), **link},
        )
    out.latency["upstream"] = (time.perf_counter() - t) * 1000
    info_out["upstream_status"] = resp.status_code

    # 4. the reply
    return await _inspect_reply(g, out, agent_id, reply, in_action, rpc_id, info_out, link)


def _block_now(g: Any, ctx: RequestCtx, findings: list[Finding], rpc_id: Any, info: dict[str, Any]) -> JSONResponse:
    engine = g.engine
    action = engine.finalize(ctx, findings)
    ctx.findings.extend(findings)
    decision = engine._decision(ctx, findings, action, "input")
    engine.finish(ctx, decision.action, direction="input", extra={"a2a": info})
    if not decision.blocked:  # monitor mode: recorded only; the caller still gets a refusal it can act on
        return rpc_error(rpc_id, BLOCKED, f"[Bouncer] {findings[0].message} (trace {ctx.trace_id})", 403, {"action": "log", "code": findings[0].id, "trace_id": ctx.trace_id})
    return _rpc_block(ctx, decision.action, decision.code, decision.message, rpc_id)


async def _inspect_reply(g: Any, ctx: RequestCtx, agent_id: str, reply: dict[str, Any], in_action: Action, rpc_id: Any, info: dict[str, Any], link: dict[str, str]) -> JSONResponse:
    engine = g.engine
    doc = ctx.doc
    reply = copy.deepcopy(reply)
    result = _drop_metadata(reply.get("result")) if "result" in reply else None
    error = reply.get("error") if isinstance(reply.get("error"), dict) else None
    lists = _parts_lists(result, [])
    if error is not None and isinstance(error.get("message"), str):
        lists.append([{"kind": "text", "text": error["message"]}])
        error = {k: v for k, v in error.items() if k != "data"}  # error data is free-form: not passed on
    who = f"agent {agent_id}"
    src = f"tool_result:a2a.{agent_id}"
    cleaned: list[tuple[Segment, str, list[Finding]]] = []
    per_part: list[tuple[list[Any], int, Segment, str, list[Finding]]] = []
    findings: list[Finding] = []
    chars = 0
    withheld = 0
    for li, plist in enumerate(lists):
        for pi, p in enumerate(plist):
            text = _part_text(p) if isinstance(p, dict) else None
            if text is None:
                plist[pi] = _withheld(p, who)
                withheld += 1
                continue
            chars += len(text)
            seg = Segment(text, "tool_result", src, False, ("a2a", li, pi), tool=f"a2a.{agent_id}")
            clean, seg_f, _ = engine.scan_segment(ctx, seg)
            # the caller may render the reply: the output checks (markdown/HTML exfiltration) apply too
            clean2, out_f = engine.scan_output_text(ctx, clean, seg.location)
            out_f = [f for f in out_f if f.control == "output_safety"]
            if clean2 != clean:
                for f in out_f:
                    if f.action == Action.REDACT:
                        f.action = Action.BLOCK
                        f.span = None
            seg_f = seg_f + out_f
            cleaned.append((seg, clean, seg_f))
            per_part.append((plist, pi, seg, clean, seg_f))
            findings.extend(seg_f)
    if withheld:
        ctx.notes.append(f"{withheld} non-text part(s) of the reply withheld (not checked)")
    if chars > doc.a2a.max_message_chars:
        findings.append(_size_finding(g, ctx, chars, doc.a2a.max_message_chars, f"reply of agent {agent_id}", "output"))
    pi_cfg = doc.controls.prompt_injection
    if pi_cfg is not None and pi_cfg.enabled and cleaned and not engine._enforced_block(ctx, findings):
        findings.extend(await engine._semantic_injection(ctx, cleaned, pi_cfg))
    action = engine.finalize(ctx, findings)
    ctx.findings.extend(findings)
    decision = engine._decision(ctx, findings, action, "output")
    overall = max(in_action, action)
    first = per_part[0][3] if per_part else ""
    ctx.excerpt = f"from {agent_id}: {engine.audit_mask(ctx, first, 'tool_result')}"[: doc.audit.excerpt_chars]
    if decision.blocked:
        engine.finish(ctx, overall, direction="output", extra={"a2a": info})
        return _rpc_block(ctx, overall, decision.code, f"The reply of agent {agent_id} was withheld. {decision.message}", rpc_id, link)

    for plist, pi, _seg, clean, seg_f in per_part:
        red = [f for f in seg_f if (f.effective_action or f.action) == Action.REDACT and f.span is not None]
        new_text = apply_redactions(clean, red)
        if new_text != _part_text(plist[pi]):
            plist[pi] = _with_text(plist[pi], new_text)
    # the reply is content from another agent: untrusted for the lethal trifecta in this session
    g.store.mark_taint(ctx.session_id, "untrusted", f"a2a.{agent_id}")
    if any(f.control == "pii" for f in findings):
        g.store.mark_taint(ctx.session_id, "sensitive", f"pii in reply of {agent_id}")
    g.store.session(ctx.session_id).steps += 1  # budgets.sessions.max_steps also limits agent ping-pong
    meta = {"action": overall.label, "trace_id": ctx.trace_id, "request_trace_id": info.get("request_trace_id"), "policy_version": ctx.policy.version, "findings": sorted({f.id for f in ctx.findings})}
    out: dict[str, Any] = {"jsonrpc": "2.0", "id": reply.get("id", rpc_id)}
    if error is not None:
        if lists and lists[-1] and isinstance(lists[-1][0], dict):
            error = {**error, "message": lists[-1][0].get("text", "")}
        out["error"] = {**error, "data": {"bouncer": meta}}
    else:
        if isinstance(result, dict):
            result["metadata"] = {"bouncer": meta}
        out["result"] = result
    engine.finish(ctx, overall, direction="output", extra={"a2a": info})
    return JSONResponse(out, headers={**bouncer_headers(ctx, overall, ctx.policy.version), **link})


# ---------------------------------------------------------------------- agent card
@router.get("/a2a/{agent_id}/.well-known/agent.json")
@router.get("/a2a/{agent_id}/.well-known/agent-card.json")
async def a2a_card(request: Request, agent_id: str) -> Any:
    g = gw(request)
    principal = authenticate(g, request)
    if principal is None:
        return unauthorized(g, CARD_ROUTE)
    principal, denied = delegation(g, request, principal, CARD_ROUTE)
    if denied is not None:
        return denied
    engine = g.engine
    ctx = engine.begin(principal, CARD_ROUTE, f"a2a_card_{agent_id[:64]}", None)
    ctx.direction = "tool_definition"
    info: dict[str, Any] = {"agent": agent_id[:64]}
    findings = _agent_findings(g, ctx, agent_id)
    if not findings:
        agent = ctx.doc.a2a.agents[agent_id]
        url = card_url(agent_id, agent)
        info["card_url"] = url
        t = time.perf_counter()
        try:
            async with _client(g, ctx.doc.a2a.timeout_seconds) as client:
                resp = await client.get(url)
            card = resp.json()
            if resp.status_code >= 400 or not isinstance(card, dict):
                raise ValueError(f"HTTP {resp.status_code}, not an agent card")
        except (httpx.HTTPError, ValueError) as exc:
            detail = f"{type(exc).__name__}: {exc}"[:300]
            ctx.findings.append(_upstream_finding(g, agent_id, detail))
            engine.finish(ctx, Action.ALLOW, direction="tool_definition", extra={"a2a": info, "upstream_error": detail}, status_code=502, message=f"Agent card of {agent_id} unavailable: {detail[:200]}")
            return JSONResponse(error_body("gateway.upstream_error", f"Agent card of {agent_id} unavailable: {detail}. Check that the agent is running.", ctx.trace_id, etype="upstream_error"), status_code=502, headers=bouncer_headers(ctx, Action.ALLOW, ctx.policy.version))
        ctx.latency["upstream"] = (time.perf_counter() - t) * 1000
        text = "\n".join(s for s in _string_leaves(_drop_metadata(card)) if s.strip())
        seg = Segment(text, "tool_definition", f"tool_definition:a2a.{agent_id}", False, ("card",), tool=f"a2a.{agent_id}")
        clean, findings, _ = engine.scan_segment(ctx, seg)
        for f in findings:  # a card cannot be rewritten in place: anything that would be redacted blocks it
            if f.action == Action.REDACT:
                f.action = Action.BLOCK
                f.message += " An agent card cannot be rewritten in place, so it was withheld; remove the value from the card."
        pi_cfg = ctx.doc.controls.prompt_injection
        if pi_cfg is not None and pi_cfg.enabled and not engine._enforced_block(ctx, findings):
            findings = findings + await engine._semantic_injection(ctx, [(seg, clean, findings)], pi_cfg)
        ctx.excerpt = engine.audit_mask(ctx, clean, "tool_definition")[: ctx.doc.audit.excerpt_chars]
    action = engine.finalize(ctx, findings)
    ctx.findings.extend(findings)
    decision = engine._decision(ctx, findings, action, "input")
    engine.finish(ctx, decision.action, direction="tool_definition", extra={"a2a": info})
    headers = bouncer_headers(ctx, decision.action, ctx.policy.version)
    if decision.blocked:
        msg = decision.message if decision.code == "auth.a2a_not_allowed" else f"The agent card of {agent_id} was withheld. {decision.message}"
        return JSONResponse(error_body(decision.code, msg, ctx.trace_id, decision.approval_id), status_code=decision.status, headers=headers)
    card = _drop_metadata(card)
    card["url"] = str(request.base_url).rstrip("/") + f"/a2a/{agent_id}"  # clients keep calling through Bouncer
    return JSONResponse(card, headers=headers)
