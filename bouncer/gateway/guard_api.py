"""POST /v1/guard/check: the control API for any integration (agent-to-agent, MCP, custom apps).

Input: a piece of text with its direction, or a planned tool call. Output: the decision, the
findings and the redacted text. Nothing is forwarded anywhere.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bouncer.core import Action, Finding, Segment
from bouncer.gateway.openai_proxy import authenticate, bouncer_headers, delegation, gw, unauthorized
from bouncer.pipeline import apply_redactions

router = APIRouter()


class ToolCallIn(BaseModel):
    name: str
    arguments: dict[str, Any] | str = {}


class GuardRequest(BaseModel):
    text: str | None = None
    direction: Literal["input", "output", "tool_result", "tool_definition"] = "input"
    source: str = "user"  # user | system | tool_result:<tool> | tool_definition:<tool> | assistant
    user_request: str | None = None
    tool_call: ToolCallIn | None = None
    session_id: str | None = None


@router.post("/v1/guard/check")
async def guard_check(request: Request, payload: GuardRequest) -> Any:
    g = gw(request)
    principal = authenticate(g, request)
    if principal is None:
        return unauthorized(g, "guard.check")
    principal, denied = delegation(g, request, principal, "guard.check")
    if denied is not None:
        return denied
    result = await run_guard(g, principal, payload, route="guard.check")
    return JSONResponse(result["body"], headers=result["headers"])


async def run_guard(g: Any, principal: Any, payload: GuardRequest, route: str = "guard.check") -> dict[str, Any]:
    sid = payload.session_id or f"guard_{principal.id}"
    ctx = g.engine.begin(principal, route, sid, None)
    findings: list[Finding] = []
    redacted = None
    body: dict[str, Any] = {"messages": []}
    if payload.user_request:
        ctx.user_request = payload.user_request
        body["messages"].append({"role": "user", "content": payload.user_request})
    if payload.text is not None:
        role = payload.source.split(":", 1)[0]
        tool = payload.source.split(":", 1)[1] if ":" in payload.source else None
        trusted = role in ("system", "assistant")
        seg = Segment(payload.text, payload.direction, payload.source, trusted, ("text",), tool=tool)
        if payload.direction == "output":
            clean, seg_findings = g.engine.scan_output_text(ctx, payload.text)
        else:
            clean, seg_findings, _ = g.engine.scan_segment(ctx, seg, use_cache=True)
            pi = ctx.doc.controls.prompt_injection
            if pi is not None and pi.enabled:
                seg_findings = seg_findings + await g.engine._semantic_injection(ctx, [(seg, clean, seg_findings)], pi)
            if payload.direction == "tool_result" and tool:
                tg = ctx.doc.controls.tool_governance
                if tg is not None and tool in tg.untrusted_source_tools:
                    g.store.mark_taint(sid, "untrusted", tool)
                if tg is not None and tool in tg.sensitive_source_tools:
                    g.store.mark_taint(sid, "sensitive", tool)
        findings.extend(seg_findings)
        ctx.excerpt = clean[: ctx.doc.audit.excerpt_chars]
        ctx.direction = payload.direction
    if payload.tool_call is not None:
        args = payload.tool_call.arguments
        tc = {"id": "guard", "type": "function", "function": {"name": payload.tool_call.name, "arguments": args if isinstance(args, str) else json.dumps(args)}}
        ctx.scan.extra["body"] = body
        findings.extend(await g.engine.inspect_tool_calls(ctx, body, [tc], ("tool_call",)))
        ctx.direction = "tool_call"
        if not ctx.excerpt:
            ctx.excerpt = f"{payload.tool_call.name}({tc['function']['arguments'][:200]})"
    action = g.engine.finalize(ctx, findings)
    ctx.findings.extend(findings)
    decision = g.engine._decision(ctx, findings, action, "input")
    if payload.text is not None:
        red = [f for f in findings if f.effective_action == Action.REDACT and f.span is not None and f.location == ("text",)]
        redacted = apply_redactions(clean, red)
    if decision.action < Action.REQUIRE_APPROVAL and payload.tool_call is not None:
        for rec in ctx.tool_calls:
            g.store.record_tool_call(sid, rec["call_hash"])
    event = g.engine.finish(ctx, decision.action, direction=ctx.direction)
    body_out = {
        "action": decision.action.label,
        "allowed": decision.action < Action.REQUIRE_APPROVAL,
        "code": decision.code,
        "message": decision.message or None,
        "approval_id": decision.approval_id,
        "redacted_text": redacted,
        "findings": [f.to_dict() for f in findings],
        "trace_id": ctx.trace_id,
        "latency_ms": event.get("latency_ms"),
        "judge": event.get("judge"),
        "policy_version": ctx.policy.version,
    }
    return {"body": body_out, "headers": bouncer_headers(ctx, decision.action, ctx.policy.version), "event": event}
