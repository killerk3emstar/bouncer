"""MCP gateway: Bouncer between MCP clients and an upstream MCP server.

Endpoint: /mcp on the gateway port (MCP streamable HTTP). The client authenticates with the same
Bouncer key as the OpenAI proxy (Authorization: Bearer <key>) and speaks MCP to Bouncer; Bouncer
speaks MCP to the upstream server (env BOUNCER_MCP_UPSTREAM, default the demo-bank server at
http://127.0.0.1:8703/mcp). The client's Authorization header is never forwarded upstream.

What is enforced (policy: controls.supply_chain.mcp, tool_governance, the text controls):
- Server allowlist: the upstream's self-reported server name must match
  supply_chain.mcp.servers_allow, otherwise no tool is served (supply_chain.mcp_server_not_allowed).
- Definition pinning (supply_chain.mcp.pin_tool_definitions): each tool definition is hashed
  (sha256 of canonical JSON of name, description, inputSchema). The first clean definition seen is
  pinned. A later, different definition ("rug pull") is hidden from tools/list and calls to the tool
  are blocked (mcp_pinning.definition_changed) until a human approves the new definition; an
  approved request re-pins the tool to the new hash.
- Tool poisoning: every definition is scanned as untrusted text (direction tool_definition) by the
  T0 controls, T1 and T2. A poisoned definition is hidden and calls to the tool are blocked.
- tools/call: the call goes through Engine.inspect_tool_calls (principal tool allowlist, argument
  rules, secrets and signatures in arguments, lethal trifecta from session taint, loops, approvals).
  The result is scanned as a tool_result (T0, T1/T2), redacted or withheld, and marks session taint.
- Resources and prompts are not proxied: their content is not scanned yet, so the lists are empty
  and reads are refused.

Each tools/list writes one audit event (route mcp.list) and each tools/call one event (route
mcp.call, direction tool_call when stopped before the upstream, tool_result otherwise). Blocks
reach the client as MCP tool errors (isError) whose text names the rule, the reason, the trace id
and the approval id; the same fields are in the result's _meta.bouncer.
"""

from __future__ import annotations

import contextlib
import dataclasses
import fnmatch
import hashlib
import json
import logging
import os
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.providers.proxy import FastMCPProxy, ProxyClient
from fastmcp.tools import Tool, ToolResult
from mcp.shared.exceptions import MCPError
from mcp_types import EmbeddedResource, TextContent, TextResourceContents
from starlette.requests import Request
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from bouncer.core import Action, Finding, Principal, Segment
from bouncer.gateway.openai_proxy import bearer, unauthorized
from bouncer.messages import parse_args
from bouncer.pipeline import RequestCtx, apply_redactions

log = logging.getLogger("bouncer.mcp")

DEFAULT_UPSTREAM = "http://127.0.0.1:8703/mcp"
SERVER_NAME_TTL_SECONDS = 60.0
# JSON-RPC implementation-defined server error used for refusals that have no isError channel
# (tools/list, resources, prompts).
BOUNCER_ERROR_CODE = -32001


class UpstreamUnavailable(Exception):
    pass


# ---------------------------------------------------------------------------- definitions


def definition_payload(tool: Any) -> dict[str, Any]:
    """The parts of a tool definition that are pinned: name, description, input schema."""
    return {
        "name": tool.name,
        "description": tool.description or "",
        "inputSchema": getattr(tool, "parameters", None) or {},
    }


def definition_hash(tool: Any) -> str:
    canonical = json.dumps(definition_payload(tool), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def definition_text(tool: Any) -> str:
    """Text scanned by the controls; same layout as OpenAI tool definitions in bouncer.messages."""
    p = definition_payload(tool)
    return f"{p['name']}\n{p['description']}\n{json.dumps(p['inputSchema'], ensure_ascii=False)}"


@dataclass
class ToolVerdict:
    """What Bouncer decided about one tool definition the last time it was listed."""

    server: str
    name: str
    hash: str
    status: str  # new_pin | pinned | repinned | changed | unpinned | not_pinned
    pinned_hash: str | None
    findings: list[Finding] = field(default_factory=list)
    hidden: bool = False
    poisoned: bool = False
    approval_id: str | None = None
    checked_at: float = 0.0
    description: str = ""

    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if (f.effective_action or f.action) >= Action.REQUIRE_APPROVAL]

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "tool": self.name,
            "hash": self.hash,
            "pinned_hash": self.pinned_hash,
            "status": self.status,
            "hidden": self.hidden,
            "poisoned": self.poisoned,
            "approval_id": self.approval_id,
            "findings": [f.id for f in self.findings],
            "checked_at": self.checked_at,
        }


# ---------------------------------------------------------------------------- gateway


class McpGateway:
    """Owns the FastMCP proxy, the per-tool verdicts and the decision logic."""

    def __init__(self, g: Any, upstream: Any = None, recheck_seconds: float | None = None) -> None:
        self.g = g
        self.upstream: Any = upstream if upstream is not None else os.environ.get("BOUNCER_MCP_UPSTREAM", DEFAULT_UPSTREAM)
        self.configured_name = os.environ.get("BOUNCER_MCP_SERVER") or None
        # Definitions are re-read from the upstream before a call when the last check is older than
        # this. 0 = before every call, so a definition changed on the server is caught even if the
        # client never lists the tools again.
        if recheck_seconds is None:
            recheck_seconds = float(os.environ.get("BOUNCER_MCP_RECHECK_SECONDS", "0"))
        self.recheck_seconds = recheck_seconds
        self.local_principal: str | None = None  # principal for in-process use without HTTP (tests, tools)
        self._base_client = ProxyClient(self.upstream)
        self._server_name: str | None = None
        self._server_name_at = 0.0
        self.verdicts: dict[tuple[str, str], ToolVerdict] = {}
        self.checked_at: dict[str, float] = {}
        self._lock = threading.RLock()
        self.proxy = FastMCPProxy(
            client_factory=self._client_factory,
            provider_error_strategy="raise",
            name="bouncer",
            instructions="Bouncer MCP gateway. Tools come from an upstream MCP server after policy checks.",
        )
        # outermost, so every request passes Bouncer before the proxy's own middleware
        self.proxy.middleware.insert(0, BouncerMcpMiddleware(self))

    # ------------------------------------------------------------------ upstream
    def set_upstream(self, target: Any) -> None:
        self.upstream = target
        self._base_client = ProxyClient(target)
        self._server_name = None
        self._server_name_at = 0.0

    def upstream_label(self) -> str:
        if isinstance(self.upstream, str):
            return self.upstream
        return f"in-process:{getattr(self.upstream, 'name', type(self.upstream).__name__)}"

    def _client_factory(self, mode: str | None = None) -> Any:
        """A fresh upstream client per request; inbound headers (the Bouncer key) are not forwarded.

        By default the client mirrors the protocol era of the front connection (as FastMCP's own proxy
        factory does); `mode` pins it instead.
        """
        fresh = self._base_client.new()
        opts = fresh._transport_options
        mode = mode or _front_era_mode()
        if mode is not None:
            fresh.mode = mode
            opts = dataclasses.replace(opts, backend_mode=mode)
        fresh._transport_options = dataclasses.replace(opts, forward_incoming_headers=False)
        return fresh

    async def server_name(self) -> str:
        now = time.monotonic()
        if self._server_name and now - self._server_name_at < SERVER_NAME_TTL_SECONDS:
            return self._server_name
        # negotiated ("auto"), not mirrored: a pinned modern version reports a synthesized, empty identity
        client = self._client_factory(mode="auto")
        try:
            async with client:
                info = client.server_info
        except Exception as exc:  # any connect failure: the upstream is not usable
            raise UpstreamUnavailable(_describe(exc)) from exc
        name = (getattr(info, "name", None) if info is not None else None) or self.configured_name or "unknown"
        self._server_name, self._server_name_at = name, now
        return name

    def reset(self) -> None:
        with self._lock:
            self.verdicts.clear()
            self.checked_at.clear()
            self._server_name = None
            self._server_name_at = 0.0

    # ------------------------------------------------------------------ request identity
    def identify(self, context: MiddlewareContext[Any]) -> tuple[Principal | None, str, str]:
        policy = self.g.policies.current
        req = _http_request()
        mcp_sid = None
        fctx = context.fastmcp_context
        if fctx is not None:
            with contextlib.suppress(Exception):
                mcp_sid = fctx.session_id
        if req is not None:
            principal = policy.principal_for_key(bearer(req))
            sid = req.headers.get("x-bouncer-session")
            user_request = unquote(req.headers.get("x-bouncer-user-request", ""))[:2000]
        else:
            principal = policy.principal(self.local_principal) if self.local_principal else None
            sid, user_request = None, ""
        if principal is None:
            return None, "", ""
        sid = (sid or (f"mcp_{mcp_sid}" if mcp_sid else f"mcp_{principal.id}"))[:128]
        return principal, sid, user_request

    # ------------------------------------------------------------------ helpers
    def finalize(self, ctx: RequestCtx, findings: list[Finding]) -> Action:
        """Engine.finalize plus supply_chain.mode for mcp_pinning findings (pinning lives in that section)."""
        overall = self.g.engine.finalize(ctx, findings)
        sc = ctx.doc.controls.supply_chain
        if sc is not None and (sc.mode or ctx.doc.defaults.mode) == "monitor":
            overall = Action.ALLOW
            for f in findings:
                if f.control == "mcp_pinning" and (f.effective_action or f.action) > Action.LOG:
                    f.effective_action = Action.LOG
                    f.monitor = True
                overall = max(overall, f.effective_action or f.action)
        return overall

    def server_findings(self, ctx: RequestCtx, server: str) -> list[Finding]:
        sc = ctx.doc.controls.supply_chain
        if sc is None or not sc.enabled:
            return []
        allow = list(sc.mcp.servers_allow)
        if any(fnmatch.fnmatchcase(server, pat) for pat in allow):
            return []
        f = self.g.engine._finding(
            "supply_chain",
            "mcp_server_not_allowed",
            Action.BLOCK,
            f"MCP server '{server}' ({self.upstream_label()}) is not in supply_chain.mcp.servers_allow "
            f"({', '.join(allow) or 'empty'}), so Bouncer serves none of its tools. Add the server to the "
            "allowlist after a security review, or point BOUNCER_MCP_UPSTREAM at an approved server.",
            severity="high",
            evidence=f"server={server}",
        )
        f.direction, f.source = "tool_definition", f"mcp_server:{server}"
        return [f]

    def error_result(self, ctx: RequestCtx, action: Action, code: str | None, message: str, approval_id: str | None) -> ToolResult:
        parts = [f"rule {code}"] if code else []
        parts.append(f"trace {ctx.trace_id}")
        if approval_id:
            parts.append(f"approval {approval_id}")
        text = f"[Bouncer] {message} ({', '.join(parts)})"
        meta = {
            "bouncer": {
                "action": action.label,
                "code": code,
                "message": message,
                "trace_id": ctx.trace_id,
                "approval_id": approval_id,
                "policy_version": ctx.policy.version,
            }
        }
        return ToolResult(content=[TextContent(type="text", text=text)], meta=meta, is_error=True)

    def mcp_error(self, ctx: RequestCtx, action: Action, code: str | None, message: str) -> MCPError:
        data = {"bouncer": {"action": action.label, "code": code, "message": message, "trace_id": ctx.trace_id, "policy_version": ctx.policy.version}}
        suffix = f" (rule {code}, trace {ctx.trace_id})" if code else f" (trace {ctx.trace_id})"
        return MCPError(BOUNCER_ERROR_CODE, f"[Bouncer] {message}{suffix}", data)

    def upstream_finding(self, ctx: RequestCtx, detail: str) -> Finding:
        f = self.g.engine._finding(
            "gateway",
            "upstream_error",
            Action.LOG,
            f"Upstream MCP server call failed: {detail}. Check that {self.upstream_label()} is running.",
            severity="low",
        )
        f.effective_action = Action.LOG
        return f

    # ------------------------------------------------------------------ definitions
    async def evaluate(self, ctx: RequestCtx, server: str, tools: Sequence[Tool]) -> dict[str, ToolVerdict]:
        """Scan and pin every definition; returns one verdict per tool and remembers them."""
        engine = self.g.engine
        doc = ctx.doc
        cleaned: list[tuple[Segment, str, list[Finding]]] = []
        for i, t in enumerate(tools):
            seg = Segment(definition_text(t), "tool_definition", f"tool_definition:{t.name}", False, ("tools", i), tool=t.name)
            clean, seg_findings, _ = engine.scan_segment(ctx, seg)
            cleaned.append((seg, clean, seg_findings))
        by_tool: dict[str, list[Finding]] = {seg.tool or "": list(fs) for seg, _, fs in cleaned}
        pi = doc.controls.prompt_injection
        if pi is not None and pi.enabled and cleaned:
            for f in await engine._semantic_injection(ctx, cleaned, pi):
                target = f.source.split(":", 1)[1] if f.source.startswith("tool_definition:") else None
                if target in by_tool:
                    by_tool[target].append(f)
                else:  # e.g. the classifier failed: applies to every definition (fail_mode decides)
                    for name in by_tool:
                        by_tool[name].append(dataclasses.replace(f, source=f"tool_definition:{name}", direction="tool_definition"))
        sc = doc.controls.supply_chain
        pin_on = sc is not None and sc.enabled and sc.mcp.pin_tool_definitions
        store = self.g.store
        now = time.time()
        out: dict[str, ToolVerdict] = {}
        with self._lock:
            for t in tools:
                h = definition_hash(t)
                findings = by_tool.get(t.name, [])
                poisoned = self.finalize(ctx, findings) >= Action.REQUIRE_APPROVAL
                v = ToolVerdict(server, t.name, h, "unpinned", None, findings, poisoned=poisoned, checked_at=now, description=(t.description or "")[:400])
                if pin_on:
                    pins = store.mcp_pins[server]
                    pinned = pins.get(t.name)
                    if pinned is None:
                        if poisoned:
                            v.status = "not_pinned"  # a poisoned definition is never pinned
                        else:
                            pins[t.name] = h
                            v.status = "new_pin"
                    elif pinned == h:
                        v.status = "pinned"
                    else:
                        appr = self._pin_approval(server, t.name, h)
                        if appr is not None and appr.status == "approved":
                            pins[t.name] = h
                            store.mcp_pending[server].pop(t.name, None)
                            v.status, v.approval_id = "repinned", appr.id
                        else:
                            if appr is None and doc.approvals.enabled:
                                appr = self._create_pin_approval(ctx, server, t, h, pinned)
                            store.mcp_pending[server][t.name] = h
                            v.status = "changed"
                            v.approval_id = appr.id if appr is not None else None
                            f = self._changed_finding(ctx, server, t.name, pinned, h, appr)
                            self.finalize(ctx, [f])
                            findings.insert(0, f)  # the rug pull is the headline when content findings tie
                    v.pinned_hash = pins.get(t.name)
                v.hidden = bool(v.blocking())
                out[t.name] = v
                self.verdicts[(server, t.name)] = v
            # tools that disappeared from the server are forgotten (pins stay)
            for key in [k for k in self.verdicts if k[0] == server and k[1] not in out]:
                self.verdicts.pop(key, None)
            self.checked_at[server] = time.monotonic()
        return out

    def _pin_approval(self, server: str, tool: str, h: str) -> Any:
        """The most relevant approval for re-pinning this definition: approved > pending > denied."""
        rank = {"approved": 0, "pending": 1, "denied": 2}
        best = None
        for appr in self.g.store.list_approvals():
            if appr.tool != f"{server}/{tool}" or appr.call_hash != _bare(h) or appr.status not in rank:
                continue
            if best is None or rank[appr.status] < rank[best.status]:
                best = appr
        return best

    def _create_pin_approval(self, ctx: RequestCtx, server: str, tool: Tool, h: str, pinned: str) -> Any:
        summary = json.dumps(
            {"new_description": (tool.description or "")[:400], "new_hash": h, "pinned_hash": pinned},
            ensure_ascii=False,
        )
        return self.g.store.create_approval(
            principal=ctx.principal.id,
            team=ctx.principal.team,
            session_id=ctx.session_id,
            call_hash=_bare(h),  # the dashboard shows it as "sha256:" + call_hash
            tool=f"{server}/{tool.name}",
            arguments_masked=summary,
            reason=(
                f"MCP server {server} changed the definition of {tool.name}. Approve only if the new name, "
                "description and input schema are expected; approving re-pins the tool to the new definition."
            ),
            finding_ids=["mcp_pinning.definition_changed"],
            trace_id=ctx.trace_id,
            ttl_seconds=ctx.doc.approvals.ttl_seconds,
        )

    def _changed_finding(self, ctx: RequestCtx, server: str, tool: str, pinned: str, h: str, appr: Any) -> Finding:
        if appr is None:
            nxt = (
                "Approvals are disabled in the policy, so restore the pinned definition on the server or "
                "restart the gateway to clear the pins."
            )
        elif appr.status == "denied":
            nxt = f"A human denied this definition ({appr.id}); restore the pinned definition on the server."
        else:
            nxt = f"Approve request {appr.id} in the dashboard if the change is expected; that re-pins the tool."
        f = self.g.engine._finding(
            "mcp_pinning",
            "definition_changed",
            Action.BLOCK,
            f"Tool {tool} on MCP server {server} changed its definition after it was pinned (rug pull: a changed "
            f"name, description or schema can carry new instructions for the model). The tool is hidden and "
            f"calls are blocked until the new definition is re-approved. {nxt}",
            severity="critical",
            evidence=f"pinned={pinned[:23]} current={h[:23]}",
        )
        f.direction, f.source, f.location = "tool_definition", f"tool_definition:{tool}", ("tools", tool)
        return f

    def hidden_for_principal(self, ctx: RequestCtx, tool: str) -> bool:
        """Tools the principal may not call are left out of its tools/list (least privilege)."""
        tg = ctx.doc.controls.tool_governance
        if tg is None or not tg.enabled or tool in ctx.principal.tools:
            return False
        probe = self.g.engine._finding("tool_governance", "unknown_tool", tg.unknown_tool, "", severity="high")
        return self.g.engine.finalize(ctx, [probe]) >= Action.REQUIRE_APPROVAL

    async def refresh(self, principal: Principal, sid: str, server: str) -> None:
        """Re-read definitions from the upstream (before a call); audits only when something changed."""
        ctx = self.g.engine.begin(principal, "mcp.list", sid, None)
        ctx.direction = "tool_definition"
        before = {k[1]: (_state(v.status), v.hash) for k, v in self.verdicts.items() if k[0] == server}
        tools = await self.proxy.list_tools(run_middleware=False)
        verdicts = await self.evaluate(ctx, server, tools)
        changed = [n for n, v in verdicts.items() if before.get(n) != (_state(v.status), v.hash)]
        if changed:
            self.finish_list(ctx, server, verdicts, served=None, note="definitions re-checked before tools/call")

    def finish_list(self, ctx: RequestCtx, server: str, verdicts: dict[str, ToolVerdict], served: list[str] | None, note: str = "", not_allowed: list[str] | None = None) -> None:
        findings = [f for v in verdicts.values() for f in v.findings]
        ctx.findings.extend(findings)
        action = self.finalize(ctx, findings)
        hidden = [n for n, v in verdicts.items() if v.hidden]
        parts = []
        for v in verdicts.values():
            if v.hidden:
                top = _top(v.blocking())
                parts.append(f"{v.name} hidden ({top.id if top else 'blocked'})")
        new_pins = [n for n, v in verdicts.items() if v.status == "new_pin"]
        repinned = [n for n, v in verdicts.items() if v.status == "repinned"]
        if new_pins:
            parts.append(f"pinned {', '.join(new_pins)}")
        if repinned:
            parts.append(f"re-pinned after approval: {', '.join(repinned)}")
        head = f"tools/list from MCP server {server}: {len(verdicts) - len(hidden)} of {len(verdicts)} definitions clean"
        if note:
            head = f"{head} ({note})"
        message = head + (". " + "; ".join(parts) if parts else "") + "."
        top = _top([f for f in findings if (f.effective_action or f.action) >= Action.REQUIRE_APPROVAL])
        if top is not None:
            message += f" {top.message}"
        ctx.approval_id = next((v.approval_id for v in verdicts.values() if v.status == "changed" and v.approval_id), None)
        ctx.excerpt = ", ".join(f"{n}{' (hidden)' if verdicts[n].hidden else ''}" for n in verdicts)[: ctx.doc.audit.excerpt_chars]
        extra = {
            "mcp": {
                "server": server,
                "upstream": self.upstream_label(),
                "served": served,
                "hidden": hidden,
                "not_allowed_for_principal": not_allowed or [],
                "tools": [v.to_dict() for v in verdicts.values()],
            }
        }
        self.g.engine.finish(ctx, action, direction="tool_definition", extra=extra, status_code=200, message=message)

    # ------------------------------------------------------------------ dashboard
    async def api_tools(self) -> dict[str, Any]:
        doc = self.g.policies.current.doc
        sc = doc.controls.supply_chain
        return {
            "upstream": self.upstream_label(),
            "server": self._server_name,
            "servers_allow": list(sc.mcp.servers_allow) if sc else [],
            "supply_chain_enabled": bool(sc is not None and sc.enabled),
            "pin_tool_definitions": bool(sc is not None and sc.enabled and sc.mcp.pin_tool_definitions),
            "tools": [v.to_dict() for v in self.verdicts.values()],
            "pins": {s: dict(p) for s, p in self.g.store.mcp_pins.items()},
            "pending": {s: dict(p) for s, p in self.g.store.mcp_pending.items()},
        }


# ---------------------------------------------------------------------------- middleware


class BouncerMcpMiddleware(Middleware):
    def __init__(self, gateway: McpGateway) -> None:
        self.gw = gateway

    # ------------------------------------------------------------------ tools/list
    async def on_list_tools(self, context: MiddlewareContext[Any], call_next: Any) -> Sequence[Tool]:
        gw = self.gw
        engine = gw.g.engine
        principal, sid, _ = gw.identify(context)
        if principal is None:
            raise MCPError(BOUNCER_ERROR_CODE, "[Bouncer] Missing or unknown Bouncer API key. Send Authorization: Bearer <key> issued for your agent.")
        ctx = engine.begin(principal, "mcp.list", sid, None)
        ctx.direction = "tool_definition"
        try:
            server = await gw.server_name()
        except UpstreamUnavailable as exc:
            raise self._upstream_list_error(ctx, str(exc)) from exc
        deny = gw.server_findings(ctx, server)
        if deny:
            action = gw.finalize(ctx, deny)
            ctx.findings.extend(deny)
            decision = engine._decision(ctx, deny, action, "input")
            if decision.blocked:
                ctx.excerpt = f"tools/list from {server}"
                engine.finish(ctx, decision.action, direction="tool_definition", extra={"mcp": {"server": server, "upstream": gw.upstream_label()}})
                raise gw.mcp_error(ctx, decision.action, decision.code, decision.message)
        t = time.perf_counter()
        try:
            tools = list(await call_next(context))
        except MCPError:
            raise
        except Exception as exc:
            raise self._upstream_list_error(ctx, _describe(exc)) from exc
        ctx.latency["upstream"] = (time.perf_counter() - t) * 1000
        verdicts = await gw.evaluate(ctx, server, tools)
        not_allowed = [x.name for x in tools if gw.hidden_for_principal(ctx, x.name)]
        visible = [x for x in tools if not verdicts[x.name].hidden and x.name not in not_allowed]
        gw.finish_list(ctx, server, verdicts, served=[x.name for x in visible], not_allowed=not_allowed)
        return visible

    def _upstream_list_error(self, ctx: RequestCtx, detail: str) -> MCPError:
        gw = self.gw
        ctx.findings.append(gw.upstream_finding(ctx, detail))
        gw.g.engine.finish(ctx, Action.ALLOW, direction="tool_definition", status_code=502, message=f"Upstream MCP server unavailable: {detail[:200]}", extra={"upstream_error": detail[:300]})
        return MCPError(
            BOUNCER_ERROR_CODE,
            f"[Bouncer] Upstream MCP server {gw.upstream_label()} is not available ({detail[:200]}). "
            f"Start it or fix BOUNCER_MCP_UPSTREAM (trace {ctx.trace_id}).",
        )

    # ------------------------------------------------------------------ tools/call
    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> ToolResult:
        gw = self.gw
        g = gw.g
        engine = g.engine
        name = str(context.message.name)
        args = dict(context.message.arguments or {})
        principal, sid, user_request = gw.identify(context)
        if principal is None:
            text = "[Bouncer] Missing or unknown Bouncer API key. Send Authorization: Bearer <key> issued for your agent."
            return ToolResult(content=[TextContent(type="text", text=text)], meta={"bouncer": {"action": "block", "code": "auth.invalid_key"}}, is_error=True)
        ctx = engine.begin(principal, "mcp.call", sid, None)
        ctx.direction = "tool_call"
        ctx.user_request = user_request
        mcp_info: dict[str, Any] = {"upstream": gw.upstream_label(), "tool": name}
        findings: list[Finding] = []

        # 1. server allowlist and the tool's definition
        try:
            server = await gw.server_name()
            mcp_info["server"] = server
            server_deny = gw.server_findings(ctx, server)
            findings.extend(server_deny)
            if not server_deny:
                verdict = await self._verdict(principal, sid, server, name)
                if verdict is not None:
                    mcp_info.update(definition_hash=verdict.hash, pin_status=verdict.status)
                    findings.extend(_for_call(verdict))
                    if verdict.status == "changed":
                        ctx.approval_id = verdict.approval_id
        except UpstreamUnavailable as exc:
            return self._upstream_call_error(ctx, str(exc), Action.ALLOW, "tool_call", mcp_info)

        # 2. circuit breaker from an earlier loop in this session
        sess = g.store.session(ctx.session_id)
        now = time.time()
        if sess.breaker_until > now:
            findings.append(
                engine._finding(
                    "loops",
                    "circuit_breaker_open",
                    Action.BLOCK,
                    f"Session {sid[:24]} is paused for {int(sess.breaker_until - now)} s after a loop "
                    f"({sess.breaker_reason}). Wait for the cooldown or start a new session.",
                    severity="medium",
                )
            )

        # 3. the call itself: allowlist, argument rules, secrets/signatures in arguments, trifecta, loops
        body: dict[str, Any] = {"messages": [{"role": "user", "content": user_request}] if user_request else []}
        ctx.scan.extra["body"] = body
        if not user_request:
            _skip_goal_alignment(ctx)  # no user request over MCP: the judge would have nothing to compare to
            mcp_info["notes"] = ["goal_alignment skipped: no user request (send X-Bouncer-User-Request)"]
        raw_args = json.dumps(args, ensure_ascii=False)
        tc = {"id": "mcp", "type": "function", "function": {"name": name, "arguments": raw_args}}
        findings.extend(await engine.inspect_tool_calls(ctx, body, [tc], ("params", "arguments")))
        tc.pop("_bouncer", None)
        fwd_args = args
        if tc["function"]["arguments"] != raw_args:  # secrets in the arguments were redacted
            parsed = parse_args(tc["function"]["arguments"])  # never falls back to the unredacted args
            fwd_args = parsed if isinstance(parsed, dict) else {"_raw": tc["function"]["arguments"]}
            if ctx.tool_calls:
                ctx.tool_calls[-1]["arguments"] = _clip_args(fwd_args)
        action = gw.finalize(ctx, findings)
        ctx.findings.extend(findings)
        decision = engine._decision(ctx, findings, action, "input")
        ctx.excerpt = f"{name}({json.dumps(_clip_args(fwd_args), ensure_ascii=False)})"[: ctx.doc.audit.excerpt_chars]
        if decision.blocked:
            engine.finish(ctx, decision.action, direction="tool_call", extra={"mcp": mcp_info})
            return gw.error_result(ctx, decision.action, decision.code, decision.message, ctx.approval_id)
        for rec in ctx.tool_calls:
            g.store.record_tool_call(ctx.session_id, rec["call_hash"])

        # 4. forward to the upstream
        if fwd_args is not args:
            context = context.copy(message=context.message.model_copy(update={"arguments": fwd_args}))
        t = time.perf_counter()
        try:
            result = await call_next(context)
        except Exception as exc:  # unknown tool, invalid arguments, upstream down: an MCP tool error, not a crash
            ctx.latency["upstream"] = (time.perf_counter() - t) * 1000
            return self._upstream_call_error(ctx, _describe(exc), decision.action, "tool_call", mcp_info)
        ctx.latency["upstream"] = (time.perf_counter() - t) * 1000
        if not isinstance(result, ToolResult) or type(result) is not ToolResult:
            # multi-round-trip results (input required) carry no content to scan
            engine.finish(ctx, decision.action, direction="tool_call", extra={"mcp": mcp_info})
            return result

        # 5. scan the result
        return await self._inspect_result(ctx, name, result, decision.action, mcp_info)

    async def _verdict(self, principal: Principal, sid: str, server: str, name: str) -> ToolVerdict | None:
        gw = self.gw
        last = gw.checked_at.get(server, 0.0)
        if (server, name) not in gw.verdicts or time.monotonic() - last >= gw.recheck_seconds:
            try:
                await gw.refresh(principal, sid, server)
            except MCPError as exc:
                raise UpstreamUnavailable(exc.message) from exc
            except Exception as exc:
                raise UpstreamUnavailable(_describe(exc)) from exc
        return gw.verdicts.get((server, name))

    async def _inspect_result(self, ctx: RequestCtx, name: str, result: ToolResult, call_action: Action, mcp_info: dict[str, Any]) -> ToolResult:
        gw = self.gw
        g = gw.g
        engine = g.engine
        doc = ctx.doc
        tg = doc.controls.tool_governance if (doc.controls.tool_governance is not None and doc.controls.tool_governance.enabled) else None
        untrusted = tg is not None and name in tg.untrusted_source_tools
        content = list(result.content or [])
        texts = [(i, b.text) for i, b in enumerate(content) if isinstance(b, TextContent)]
        # text inside embedded resources reaches the model too, so it is scanned like any other text
        texts += [
            (i, b.resource.text)
            for i, b in enumerate(content)
            if isinstance(b, EmbeddedResource) and isinstance(b.resource, TextResourceContents) and b.resource.text
        ]
        seen = {t for _, t in texts}
        leaves = [s for s in dict.fromkeys(_string_leaves(result.structured_content)) if s not in seen and s.strip()]
        segs = [Segment(t, "tool_result", f"tool_result:{name}", not untrusted, ("content", i), tool=name) for i, t in texts]
        segs += [Segment(s, "tool_result", f"tool_result:{name}", not untrusted, ("structured", k), tool=name) for k, s in enumerate(leaves)]
        cleaned: list[tuple[Segment, str, list[Finding]]] = []
        rfindings: list[Finding] = []
        for seg in segs:
            clean, seg_findings, _ = engine.scan_segment(ctx, seg)
            cleaned.append((seg, clean, seg_findings))
            rfindings.extend(seg_findings)
        pi = doc.controls.prompt_injection
        if pi is not None and pi.enabled and cleaned:
            rfindings.extend(await engine._semantic_injection(ctx, cleaned, pi))
        raction = gw.finalize(ctx, rfindings)
        ctx.findings.extend(rfindings)
        ctx.direction = "tool_result"
        rdecision = engine._decision(ctx, rfindings, raction, "output")
        overall = max(call_action, raction)
        # redacted text per original string (content blocks and structured leaves)
        replaced: dict[str, str] = {}
        for seg, clean, seg_findings in cleaned:
            red = [f for f in seg_findings if (f.effective_action or f.action) == Action.REDACT and f.span is not None]
            replaced[seg.text] = apply_redactions(clean, red)
        first = replaced.get(texts[0][1], "") if texts else ""
        # the audit excerpt masks every secret and PII value, also when the result is blocked
        ctx.excerpt = f"{name} -> {engine.audit_mask(ctx, first, 'tool_result')}"[: doc.audit.excerpt_chars]
        mcp_info["upstream_is_error"] = bool(result.is_error)
        if rdecision.blocked:
            engine.finish(ctx, overall, direction="tool_result", extra={"mcp": mcp_info})
            msg = f"The result of {name} was withheld. {rdecision.message}"
            return gw.error_result(ctx, overall, rdecision.code, msg, ctx.approval_id)
        # delivered: mark session taint like the OpenAI path does for tool messages
        if tg is not None:
            if untrusted:
                g.store.mark_taint(ctx.session_id, "untrusted", name)
            if name in tg.sensitive_source_tools:
                g.store.mark_taint(ctx.session_id, "sensitive", name)
        if any(f.control == "pii" for f in rfindings):
            g.store.mark_taint(ctx.session_id, "sensitive", f"pii in {name} result")
        new_content = []
        for b in content:
            if isinstance(b, TextContent) and b.text in replaced and replaced[b.text] != b.text:
                new_content.append(b.model_copy(update={"text": replaced[b.text]}))
            elif isinstance(b, EmbeddedResource) and isinstance(b.resource, TextResourceContents):
                text = b.resource.text
                if text in replaced and replaced[text] != text:
                    b = b.model_copy(update={"resource": b.resource.model_copy(update={"text": replaced[text]})})
                new_content.append(b)
            elif isinstance(b, TextContent):
                new_content.append(b)
            else:
                # images, audio, binary blobs and links cannot be checked as text: withheld
                new_content.append(TextContent(type="text", text=f"[Bouncer: {getattr(b, 'type', 'non-text')} content from {name} withheld; only text results are passed through]"))
        structured = _map_strings(result.structured_content, lambda s: replaced.get(s, s)) if result.structured_content is not None else None
        meta = dict(result.meta or {})
        meta["bouncer"] = {"action": overall.label, "trace_id": ctx.trace_id, "policy_version": ctx.policy.version}
        engine.finish(ctx, overall, direction="tool_result", extra={"mcp": mcp_info})
        if not new_content:
            new_content = [TextContent(type="text", text="")]
        return ToolResult(content=new_content, structured_content=structured, meta=meta, is_error=result.is_error)

    def _upstream_call_error(self, ctx: RequestCtx, detail: str, action: Action, direction: str, mcp_info: dict[str, Any]) -> ToolResult:
        gw = self.gw
        ctx.findings.append(gw.upstream_finding(ctx, detail))
        msg = f"Upstream MCP call failed: {detail[:300]}"
        gw.g.engine.finish(ctx, action, direction=direction, extra={"mcp": mcp_info, "upstream_error": detail[:300]}, status_code=502, message=msg)
        return gw.error_result(ctx, action, "gateway.upstream_error", f"{msg}. Check that {gw.upstream_label()} is running and the tool name and arguments are valid.", None)

    # ------------------------------------------------------------------ resources and prompts are not proxied
    async def on_list_resources(self, context: MiddlewareContext[Any], call_next: Any) -> list[Any]:
        return []

    async def on_list_resource_templates(self, context: MiddlewareContext[Any], call_next: Any) -> list[Any]:
        return []

    async def on_list_prompts(self, context: MiddlewareContext[Any], call_next: Any) -> list[Any]:
        return []

    async def on_read_resource(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        raise MCPError(BOUNCER_ERROR_CODE, "[Bouncer] MCP resources are not proxied: Bouncer does not scan resource content yet. Expose the data through a tool instead.")

    async def on_get_prompt(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        raise MCPError(BOUNCER_ERROR_CODE, "[Bouncer] MCP prompts are not proxied: Bouncer does not scan prompt templates yet.")


# ---------------------------------------------------------------------------- HTTP mounting


class _AuthGate:
    """Refuses /mcp requests without a valid Bouncer key before they reach the MCP session layer."""

    def __init__(self, app: ASGIApp, gateway: McpGateway) -> None:
        self.app = app
        self.gw = gateway

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        g = self.gw.g
        request = Request(scope, receive)
        if g.policies.current.principal_for_key(bearer(request)) is None:
            route = "mcp.call"
            if scope.get("method") == "POST":  # the body is only read to label the audit event; it is not forwarded
                with contextlib.suppress(Exception):
                    msg = json.loads(await request.body())
                    if isinstance(msg, dict) and msg.get("method") == "tools/list":
                        route = "mcp.list"
            resp = unauthorized(g, route)
            resp.headers["WWW-Authenticate"] = 'Bearer realm="bouncer"'
            await resp(scope, receive, send)
            return
        await self.app(scope, receive, send)


def mount(app: Any, state: Any, upstream: Any = None) -> McpGateway:
    """Serve the MCP gateway at /mcp on the FastAPI app and run its session manager in the app lifespan."""
    gateway = McpGateway(state, upstream=upstream)
    upstream_log = logging.getLogger("httpx2")  # the MCP client logs every upstream request at INFO
    if upstream_log.level == logging.NOTSET:
        upstream_log.setLevel(logging.WARNING)
    mcp_http = gateway.proxy.http_app(path="/mcp")
    app.router.routes.append(Route("/mcp", endpoint=_AuthGate(mcp_http, gateway)))
    app.add_api_route("/api/mcp/tools", gateway.api_tools, methods=["GET"])
    previous = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(a: Any):  # noqa: ANN202
        async with previous(a) as maybe_state:
            async with mcp_http.router.lifespan_context(mcp_http):
                yield maybe_state

    app.router.lifespan_context = lifespan
    app.state.mcp = gateway
    return gateway


# ---------------------------------------------------------------------------- utilities


def _http_request() -> Request | None:
    try:
        from fastmcp.server.dependencies import get_http_request

        return get_http_request()
    except RuntimeError:
        return None


def _front_era_mode() -> str | None:
    """Mirror the client's protocol era on the upstream connection (what FastMCP's own proxy factory does)."""
    try:
        from fastmcp.server.providers.proxy import _mirror_front_era_mode

        return _mirror_front_era_mode()
    except Exception:
        return None


def _skip_goal_alignment(ctx: RequestCtx) -> None:
    doc = ctx.variant.doc
    tg = doc.controls.tool_governance
    if tg is None or not tg.goal_alignment.enabled:
        return
    ga = tg.goal_alignment.model_copy(update={"enabled": False})
    controls = doc.controls.model_copy(update={"tool_governance": tg.model_copy(update={"goal_alignment": ga})})
    ctx.variant = dataclasses.replace(ctx.variant, doc=doc.model_copy(update={"controls": controls}))


def _for_call(v: ToolVerdict) -> list[Finding]:
    """Definition findings that also stop a call to the tool (copies, so the verdict stays intact)."""
    out = []
    for f in v.blocking():
        out.append(dataclasses.replace(f, effective_action=None, monitor=False, owasp_llm=list(f.owasp_llm), owasp_agentic=list(f.owasp_agentic), atlas=list(f.atlas)))
    return out


def _bare(h: str) -> str:
    return h.removeprefix("sha256:")


def _state(status: str) -> str:
    return "pinned" if status in ("new_pin", "pinned", "repinned") else status


def _top(findings: list[Finding]) -> Finding | None:
    from bouncer.core import SEVERITY_ORDER

    best = None
    for f in findings:
        key = (f.effective_action or f.action, SEVERITY_ORDER.get(f.severity, 0), f.score)
        if best is None or key > best[0]:
            best = (key, f)
    return best[1] if best else None


def _string_leaves(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _string_leaves(v)]
    if isinstance(value, list | tuple):
        return [s for v in value for s in _string_leaves(v)]
    return []


def _map_strings(value: Any, fn: Any) -> Any:
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, dict):
        return {k: _map_strings(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [_map_strings(v, fn) for v in value]
    return value


def _clip_args(args: Any) -> Any:
    if isinstance(args, dict):
        return {k: _clip_args(v) for k, v in args.items()}
    if isinstance(args, list):
        return [_clip_args(v) for v in args[:20]]
    if isinstance(args, str) and len(args) > 300:
        return args[:300] + "...[truncated]"
    return args


def _describe(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    cause = exc.__cause__
    if cause is not None and str(cause) not in text:
        text += f" ({type(cause).__name__}: {cause})"
    return text[:500]
