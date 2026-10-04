"""JSON API for the dashboard (/api/*) and the printable management report (/reports/summary).

Shapes follow docs/API.md. Everything is computed from the in-memory audit buffer, the store and
the active policy; nothing here changes enforcement except approvals and the playground.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from bouncer.audit import csv_header, csv_line, event_epoch, now_iso
from bouncer.gateway.openai_proxy import gw, handle_chat
from bouncer.policy.compiled import CONTROL_CATALOG
from bouncer.policy.profiles import PROFILE_NOTES
from bouncer.telemetry import Telemetry

router = APIRouter()

ROOT = Path(__file__).resolve().parent.parent.parent
WINDOWS = {"1h": 3600, "24h": 86400, "7d": 7 * 86400}
ACTIONS = ["allow", "log", "redact", "require_approval", "block"]

OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}
OWASP_LLM_URL = {
    "LLM01": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    "LLM02": "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
    "LLM03": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
    "LLM04": "https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/",
    "LLM05": "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
    "LLM06": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
    "LLM07": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
    "LLM08": "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
    "LLM09": "https://genai.owasp.org/llmrisk/llm092025-misinformation/",
    "LLM10": "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/",
}
OWASP_AGENTIC = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}
AGENTIC_URL = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"

# Design coverage: which control addresses which risk, and how fully. Honest gaps stay empty.
COVERAGE_MAP: dict[str, list[tuple[str, str]]] = {
    "LLM01": [("prompt_injection", "covered"), ("obfuscation", "covered"), ("signatures", "covered")],
    "LLM02": [("secrets", "covered"), ("pii", "covered"), ("output_safety", "covered"), ("tool_governance", "covered")],
    "LLM03": [("signatures", "covered"), ("supply_chain", "covered"), ("mcp_pinning", "covered")],
    "LLM04": [("supply_chain", "partial")],
    "LLM05": [("output_safety", "covered"), ("signatures", "covered")],
    "LLM06": [("tool_governance", "covered"), ("auth", "covered"), ("approvals", "covered")],
    "LLM07": [("output_safety", "covered")],
    "LLM08": [("prompt_injection", "partial")],
    "LLM09": [],
    "LLM10": [("budgets", "covered"), ("loops", "covered")],
    "ASI01": [("prompt_injection", "covered"), ("obfuscation", "covered"), ("tool_governance", "covered")],
    "ASI02": [("tool_governance", "covered"), ("approvals", "covered")],
    "ASI03": [("auth", "partial"), ("secrets", "partial")],
    "ASI04": [("supply_chain", "covered"), ("mcp_pinning", "covered"), ("signatures", "covered")],
    "ASI05": [("signatures", "covered"), ("tool_governance", "covered")],
    "ASI06": [("prompt_injection", "covered")],
    "ASI07": [("auth", "partial")],
    "ASI08": [("budgets", "partial"), ("loops", "partial")],
    "ASI09": [("approvals", "partial")],
    "ASI10": [("tool_governance", "partial"), ("loops", "partial")],
}
COVERAGE_NOTES = {
    "LLM04": "Only model-source allowlist and trust_remote_code / unsafe deserialization signatures; training data is out of scope.",
    "LLM08": "Retrieved fragments and tool results are scanned like untrusted input; no vector store access control.",
    "LLM09": "Hallucination and misinformation are out of scope for a control layer.",
    "ASI03": "API key per agent with model/tool allowlists; delegation only where the policy allows it, with the intersection of both agents' permissions.",
    "ASI06": "Tool results are scanned before they enter the context, and content saved with memory/knowledge-base tools (tool_governance.memory_write_tools) is scanned like untrusted input.",
    "ASI07": "An agent calling for another agent (X-Bouncer-On-Behalf-Of) needs principals.<id>.may_act_for and gets the intersection of both agents' permissions; messages between agents can be checked with /v1/guard/check. Messages are not signed end to end.",
    "ASI08": "Budgets, step limits and loop breakers stop runaway sessions; no cross-agent failure isolation.",
    "ASI09": "Human approval for risky calls; no UI-level trust signals.",
    "ASI10": "Loop breakers and goal-alignment checks; no behavioral baseline per agent.",
}

DESCRIPTIONS = {
    "auth": "API key to principal; allowed models and tools per principal.",
    "secrets": "Gitleaks-style rules and entropy; secrets are redacted before they reach the model.",
    "pii": "E-mail, phone, PESEL, NIP, IBAN, cards with checksum validation; per-entity action; clearance-aware.",
    "obfuscation": "NFKC, invisible and Unicode tag characters, homoglyphs, base64/hex/url decoding; decoded copies are scanned.",
    "prompt_injection": "T0 phrase heuristics (EN/PL/DE), T1 DeBERTa classifier, T2 judge for grey zone and non-English text.",
    "tool_governance": "Tool allowlist, argument limits, lethal trifecta, T2 goal alignment for side-effect tools.",
    "budgets": "USD per team per day, per session, tokens per minute, local GPU seconds; downgrade then block.",
    "loops": "Identical tool calls, step limit, circuit breaker with cooldown.",
    "output_safety": "Markdown image/link exfiltration, HTML/script, system prompt canary.",
    "signatures": "Signed feed of historical attack signatures, reloaded without restart.",
    "supply_chain": "Model source allowlist, trust_remote_code and safetensors rules, MCP server allowlist.",
    "mcp_pinning": "Hash of each MCP tool definition; a changed definition is blocked until re-approved.",
    "approvals": "require_approval creates a request; an approval allows that exact call once, for the same agent and session, within a time window.",
    "harmful_content": "Judge question on harm categories, answered in the same pass.",
}

# Controls whose enforcement code exists in this build (others show as "not implemented").
IMPLEMENTED = {"auth", "secrets", "pii", "obfuscation", "prompt_injection", "tool_governance", "budgets", "loops", "output_safety", "signatures", "approvals", "supply_chain", "mcp_pinning"}


def _iso(ts: float | None) -> str | None:
    return now_iso(ts) if ts else None


def _events(g: Any, window_s: int | None = None, limit: int = 100000) -> list[dict[str, Any]]:
    since = time.time() - window_s if window_s else None
    return g.audit.query(limit=limit, since_ts=since, kind="decision")


def _pct(vals: list[float], p: float) -> float | None:
    return Telemetry._percentile(vals, p)


# ---------------------------------------------------------------------------- stats


@router.get("/api/stats")
async def stats(request: Request, window: str = "24h") -> dict[str, Any]:
    g = gw(request)
    secs = WINDOWS.get(window, 86400)
    now = time.time()
    evs = _events(g, secs)
    totals = {a: 0 for a in ACTIONS}
    usage = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0, "gpu_seconds": 0.0}
    bucket = secs // 24
    buckets: dict[int, dict[str, Any]] = {}
    for i in range(24):
        start = now - secs + i * bucket
        buckets[i] = {"ts": now_iso(start), **{a: 0 for a in ACTIONS}}
    top_controls: dict[str, Counter] = defaultdict(Counter)
    top_owasp: Counter = Counter()
    lat: dict[str, list[float]] = defaultdict(list)
    escalations = cache_hits = timeouts = 0
    for ev in evs:
        a = ev.get("action", "allow")
        totals[a] = totals.get(a, 0) + 1
        u = ev.get("usage") or {}
        for k in usage:
            usage[k] += u.get(k) or 0
        idx = min(23, max(0, int((event_epoch(ev) - (now - secs)) // bucket)))
        buckets[idx][a] = buckets[idx].get(a, 0) + 1
        for f in ev.get("findings", []):
            eff = f.get("effective_action") or f.get("action")
            top_controls[f.get("control", "?")][eff] += 1
            for o in (f.get("owasp_llm") or []) + (f.get("owasp_agentic") or []):
                top_owasp[o] += 1
        for layer, ms in (ev.get("latency_ms") or {}).items():
            if ms is None:
                continue
            if layer in ("t1", "t2", "upstream") and not ms:
                continue
            lat[layer].append(float(ms))
        j = ev.get("judge") or {}
        if j.get("invoked"):
            escalations += 1
            cache_hits += 1 if j.get("cached") else 0
            timeouts += 1 if j.get("error") == "timeout" else 0
    n = len(evs)
    usage["cost_usd"] = round(usage["cost_usd"], 6)
    usage["gpu_seconds"] = round(usage["gpu_seconds"], 2)
    return {
        "window": window,
        "from": now_iso(now - secs),
        "to": now_iso(now),
        "generated_at": now_iso(now),
        "totals": {"requests": n, **totals},
        "usage": usage,
        "series": {"bucket_seconds": bucket, "buckets": [buckets[i] for i in range(24)]},
        "top_controls": sorted(
            ({"control": c, **{a: cnt.get(a, 0) for a in ("log", "redact", "require_approval", "block")}, "count": sum(cnt.values())} for c, cnt in top_controls.items()),
            key=lambda x: -x["count"],
        )[:10],
        "top_owasp": [{"id": k, "name": OWASP_LLM.get(k) or OWASP_AGENTIC.get(k, k), "count": v} for k, v in top_owasp.most_common(10)],
        "latency_ms": {layer: {"n": len(v), "p50": _pct(v, 0.5), "p95": _pct(v, 0.95)} for layer, v in lat.items()},
        "t2": {
            "escalations": escalations,
            "escalation_rate": round(escalations / n, 4) if n else 0.0,
            "cache_hits": cache_hits,
            "cache_hit_rate": round(cache_hits / escalations, 4) if escalations else 0.0,
            "timeouts": timeouts,
        },
    }


# ---------------------------------------------------------------------------- events


def _filter_params(request: Request) -> dict[str, Any]:
    q = request.query_params
    return {
        "action": q.get("action") or None,
        "control": q.get("control") or None,
        "principal": q.get("principal") or None,
        "route": q.get("route") or None,
        "q": q.get("q") or None,
    }


@router.get("/api/events")
async def events(request: Request, limit: int = 100, before_seq: int | None = None) -> dict[str, Any]:
    g = gw(request)
    limit = max(1, min(limit, 1000))
    # decisions and system events (policy reloads, feed updates, approval decisions), newest first
    evs = g.audit.query(limit=limit + 1, before_seq=before_seq, kind=None, **_filter_params(request))
    nxt = evs[limit - 1]["seq"] if len(evs) > limit else None
    return {"events": evs[:limit], "next_before_seq": nxt}


@router.get("/api/events/stream")
async def events_stream(request: Request) -> StreamingResponse:
    g = gw(request)
    q = g.audit.subscribe()

    async def gen():  # noqa: ANN202
        try:
            yield ": connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=15)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(ev, ensure_ascii=False, default=str)}\n\n"
        finally:
            g.audit.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/api/events/{trace_id}")
async def event_detail(request: Request, trace_id: str) -> Any:
    g = gw(request)
    events = g.audit.trace(trace_id)
    if not events:
        return JSONResponse({"error": {"type": "not_found", "message": f"No event with trace id {trace_id} in the in-memory buffer; use the audit export for older events."}}, status_code=404)
    from bouncer.audit import chain_hash

    chain_ok = all(ev.get("hash") == chain_hash(ev.get("prev_hash", ""), ev) for ev in events if ev.get("hash"))
    return {"trace_id": trace_id, "chain_ok": chain_ok, "events": events}


# ---------------------------------------------------------------------------- controls and coverage


_CASE_COUNTS: dict[str, Any] = {"key": None, "value": None}


def _case_counts() -> dict[str, dict[str, int]]:
    """Test cases per control, re-read only when a file in tests/cases/ changes."""
    files = sorted((ROOT / "tests" / "cases").glob("*.yaml")) + [p for p in UNIT_TEST_FILES.values() if p.exists()]
    key = tuple((p.name, p.stat().st_mtime_ns) for p in files)
    if _CASE_COUNTS["key"] == key:
        return _CASE_COUNTS["value"]
    value = _read_case_counts()
    _CASE_COUNTS.update({"key": key, "value": value})
    return value


# controls whose behavior is tested with pytest unit tests rather than YAML cases (counted per test function)
UNIT_TEST_FILES = {"mcp_pinning": ROOT / "tests" / "unit" / "mcp" / "test_mcp_gateway.py"}


def _read_case_counts() -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"allow": 0, "block": 0, "total": 0})
    for ctl, path in UNIT_TEST_FILES.items():
        if path.exists():
            n = sum(1 for line in path.read_text().splitlines() if line.startswith("def test_"))
            counts[ctl]["total"] += n
            counts[ctl]["block"] += n
    for path in sorted((ROOT / "tests" / "cases").glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text()) or []
        except yaml.YAMLError:
            continue
        for c in data if isinstance(data, list) else []:
            if not isinstance(c, dict):
                continue
            ctl = c.get("control", "unknown")
            kind = c.get("kind", "")
            counts[ctl]["total"] += 1
            counts[ctl]["allow" if kind in ("allow", "log", "known_gap") else "block"] += 1
    return counts


def _control_state(g: Any, cid: str) -> dict[str, Any]:
    policy = g.policies.current
    doc = policy.doc
    variant = policy.variant()
    enabled, mode, action, settings, directions, reason = True, doc.defaults.mode, None, {}, [], None
    if cid == "auth":
        action = "block"
        settings = {"principals": len(doc.principals), "unknown_key": "401", "model_not_allowed": "403"}
        directions = ["input"]
    elif cid in ("budgets", "loops"):
        b = doc.budgets
        enabled = b is not None and b.enabled
        if not enabled:
            reason = "budgets section missing or disabled in the policy"
        else:
            mode = b.mode or doc.defaults.mode
            if cid == "budgets":
                action = b.on_exceed.action
                settings = {"teams": len(b.teams), "max_input_tokens": b.requests.max_input_tokens, "max_output_tokens": b.requests.max_output_tokens, "downgrade_to": b.on_exceed.downgrade_to}
            else:
                action = "block"
                settings = {"max_identical_tool_calls": b.sessions.max_identical_tool_calls, "loop_window_seconds": b.sessions.loop_window_seconds, "cooldown_seconds": b.sessions.loop_cooldown_seconds, "max_steps": b.sessions.max_steps}
        directions = ["input", "tool_call"]
    elif cid == "approvals":
        enabled = doc.approvals.enabled
        action = "require_approval"
        settings = {"ttl_seconds": doc.approvals.ttl_seconds}
    elif cid == "mcp_pinning":
        sc = doc.controls.supply_chain
        enabled = sc is not None and sc.enabled and sc.mcp.pin_tool_definitions
        action = "block"
        settings = {"servers_allow": sc.mcp.servers_allow if sc else []}
    else:
        cfg = getattr(doc.controls, cid, None)
        if cfg is None:
            enabled, reason = False, f"controls.{cid} is missing from the policy"
        elif not cfg.enabled:
            enabled, reason = False, f"controls.{cid}.enabled is false"
        else:
            mode = cfg.mode or doc.defaults.mode
            dump = cfg.model_dump(exclude={"enabled", "mode"})
            directions = dump.pop("directions", None) or []
            action = dump.get("action")
            if cid == "prompt_injection":
                action = cfg.heuristics.action
                settings = {"classifier.block_above": cfg.classifier.block_above, "classifier.escalate_above": cfg.classifier.escalate_above, "judge.block_above": cfg.judge.block_above, "judge.approval_above": cfg.judge.approval_above, "apply_to": cfg.apply_to}
            elif cid == "pii":
                settings = dict(cfg.entities)
                action = "per entity"
            elif cid == "tool_governance":
                action = cfg.unknown_tool
                settings = {"side_effect_tools": cfg.side_effect_tools, "lethal_trifecta": cfg.lethal_trifecta.action, "goal_alignment.block_above": cfg.goal_alignment.block_above, "argument_rules": list(cfg.arguments)}
            else:
                settings = {k: v for k, v in dump.items() if k != "action" and not isinstance(v, (dict, list)) or k in ("decode",)}
        if enabled and cid in variant.unavailable:
            enabled, reason = False, f"control failed to load: {variant.unavailable[cid]}"
    if cid not in IMPLEMENTED and enabled:
        reason = "configured in the policy, not implemented in this build"
    return {"enabled": enabled and cid in IMPLEMENTED, "mode": mode, "action": action, "settings": settings, "directions": directions, "disabled_reason": reason}


@router.get("/api/controls")
async def controls(request: Request) -> dict[str, Any]:
    g = gw(request)
    counts = _case_counts()
    last = getattr(request.app.state, "last_selftest", None)
    by_ctl = {c["control"]: c for c in (last or {}).get("by_control", [])}
    triggers: dict[str, dict[str, Any]] = defaultdict(lambda: {"count_24h": 0, "last_triggered": None})
    since = time.time() - 86400
    for ev in _events(g, None, 5000):
        for f in ev.get("findings", []):
            t = triggers[f.get("control", "?")]
            if event_epoch(ev) >= since:
                t["count_24h"] += 1
            if t["last_triggered"] is None or ev["ts"] > t["last_triggered"]:
                t["last_triggered"] = ev["ts"]
    out = []
    for cid, meta in CONTROL_CATALOG.items():
        st = _control_state(g, cid)
        c = counts.get(cid, {"allow": 0, "block": 0, "total": 0})
        res = by_ctl.get(cid, {})
        out.append(
            {
                "id": cid,
                "title": meta["title"],
                "description": DESCRIPTIONS.get(cid, ""),
                "tiers": [t for t in meta.get("tier", "T0").split("/") if t != "-"],
                "enabled": st["enabled"],
                "mode": st["mode"],
                "action": st["action"],
                "directions": st["directions"],
                "settings": st["settings"],
                "owasp_llm": meta.get("owasp_llm", []),
                "owasp_agentic": meta.get("owasp_agentic", []),
                "atlas": [],
                "tests": {
                    "allow": c["allow"],
                    "block": c["block"],
                    "total": c["total"],
                    "passed": res.get("passed"),
                    "failed": res.get("failed"),
                    "last_run": (last or {}).get("started_at"),
                },
                "triggers": triggers.get(cid, {"count_24h": 0, "last_triggered": None}),
                "disabled_reason": st["disabled_reason"],
            }
        )
    return {"policy_version": g.policies.current.version, "controls": out}


@router.get("/api/coverage")
async def coverage(request: Request) -> dict[str, Any]:
    g = gw(request)
    counts = _case_counts()
    states = {cid: _control_state(g, cid) for cid in CONTROL_CATALOG}
    risks = []
    tally = {"covered": 0, "partial": 0, "none": 0}
    by_fw: dict[str, Counter] = {"owasp_llm_2025": Counter(), "owasp_agentic_2026": Counter()}
    for rid, mapping in COVERAGE_MAP.items():
        fw = "owasp_llm_2025" if rid.startswith("LLM") else "owasp_agentic_2026"
        cells = {}
        best = "none"
        tests = 0
        for cid, level in mapping:
            st = states.get(cid, {"enabled": False, "mode": "enforce"})
            n = counts.get(cid, {}).get("total", 0)
            if not st["enabled"]:
                status = "none"
            elif st["mode"] == "monitor" or n == 0:
                status = "partial"
            else:
                status = level
            cells[cid] = {"status": status, "tests": n}
            tests += n
            if status == "covered" or (status == "partial" and best == "none"):
                best = status
        tally[best] += 1
        by_fw[fw][best] += 1
        risks.append(
            {
                "id": rid,
                "framework": fw,
                "name": OWASP_LLM.get(rid) or OWASP_AGENTIC.get(rid),
                "url": OWASP_LLM_URL.get(rid, AGENTIC_URL),
                "status": best,
                "tests": tests,
                "note": COVERAGE_NOTES.get(rid),
                "cells": cells,
            }
        )
    total = len(COVERAGE_MAP)
    enabled = [s for s in states.values() if s["enabled"]]
    last = getattr(request.app.state, "last_selftest", None) or {}
    return {
        "frameworks": [
            {"id": "owasp_llm_2025", "name": "OWASP Top 10 for LLM Applications 2025", "url": "https://genai.owasp.org/llm-top-10/"},
            {"id": "owasp_agentic_2026", "name": "OWASP Top 10 for Agentic Applications 2026", "url": AGENTIC_URL},
        ],
        "controls": list(states),
        "risks": risks,
        "posture": {
            "score": round(100 * (tally["covered"] + 0.5 * tally["partial"]) / total),
            "formula": "100 * (covered + 0.5 * partial) / total risks",
            "total": total,
            "covered": tally["covered"],
            "partial": tally["partial"],
            "not_covered": tally["none"],
            "by_framework": {k: {"total": sum(v.values()) or 10, "covered": v["covered"], "partial": v["partial"], "not_covered": v["none"]} for k, v in by_fw.items()},
            "controls": {
                "total": len(states),
                "enabled": len(enabled),
                "enforce": sum(1 for s in enabled if s["mode"] == "enforce"),
                "monitor": sum(1 for s in enabled if s["mode"] == "monitor"),
                "disabled": len(states) - len(enabled),
            },
            # after a run, passed/failed/total all come from that run (the dashboard self-test runs the YAML
            # cases only); before it, the total is every counted case including the MCP unit tests
            "tests": {"total": last.get("total") or sum(c["total"] for c in counts.values()), "passed": last.get("passed"), "failed": last.get("failed"), "last_run": last.get("started_at")},
        },
    }


# ---------------------------------------------------------------------------- policy


def _policy_summary(g: Any) -> dict[str, Any]:
    p = g.policies.current
    doc = p.doc
    err = g.policies.last_error
    fs = g.feed_store
    feed = None
    if fs is not None and hasattr(fs, "status"):
        try:
            st = fs.status()
            feed = {k: st.get(k) for k in ("name", "feed", "version", "verified", "updated")}
            feed["name"] = st.get("name") or st.get("feed")
            feed["signatures"] = st.get("count") or st.get("signature_count") or len(st.get("signatures") or [])
        except Exception:
            feed = None
    return {
        "version": p.version,
        "profile": doc.profile,
        "profile_note": PROFILE_NOTES.get(doc.profile),
        "mode": doc.defaults.mode,
        "fail_mode": doc.defaults.fail_mode,
        "block_response": doc.defaults.block_response,
        "path": str(g.policies.path),
        "loaded_at": _iso(p.loaded_at),
        "reload": {
            "status": "failed" if err else "ok",
            "at": _iso(err["at"]) if err else _iso(g.policies.last_reload_at),
            "attempted_version": err.get("attempted_version") if err else p.version,
            "error": _error_shape(err) if err else None,
            "reloads": g.policies.reload_count,
            "failed": g.policies.failed_count,
        },
        "feed": feed,
        "judge": {"backend": g.judge.backend, "url": doc.judge.url, "healthy": None, "allow_external": doc.judge.allow_external, "timeout_ms": doc.judge.timeout_ms},
        "principals": [
            {"id": pid, "team": pr.team, "profile": pr.profile or doc.profile, "data_clearance": pr.data_clearance, "models": pr.models, "tools": pr.tools}
            for pid, pr in doc.principals.items()
        ],
        "models": [
            {
                "id": mid,
                "upstream": m.upstream,
                "local": doc.upstreams[m.upstream].local,
                "price_input_per_1m": m.price_per_1m_tokens.input,
                "price_output_per_1m": m.price_per_1m_tokens.output,
                "gpu_usd_per_second": m.gpu_usd_per_second,
            }
            for mid, m in doc.models.items()
        ],
        "source": p.text,
    }


_JUDGE_HEALTH: dict[str, Any] = {"at": 0.0, "url": None, "value": None}


async def judge_health(g: Any) -> dict[str, Any] | None:
    """GET <judge.url>/health, cached for 10 s. None when the backend is in-process (fake) or none."""
    jc = g.policies.current.doc.judge
    backend = g.judge.backend
    if backend in ("fake", "none"):
        return {"healthy": True, "detail": f"{backend} backend runs in-process"} if backend == "fake" else None
    now = time.time()
    if _JUDGE_HEALTH["url"] == jc.url and now - _JUDGE_HEALTH["at"] < 10:
        return _JUDGE_HEALTH["value"]
    import httpx

    try:
        async with httpx.AsyncClient(timeout=1.0) as c:
            r = await c.get(jc.url.rstrip("/") + "/health")
            body = r.json()
            value = {"healthy": r.status_code == 200 and body.get("status") == "ok", "detail": body}
    except Exception as exc:
        value = {"healthy": False, "detail": f"{type(exc).__name__}: {exc}"[:200]}
    _JUDGE_HEALTH.update({"at": now, "url": jc.url, "value": value})
    return value


@router.get("/api/policy")
async def policy(request: Request) -> dict[str, Any]:
    g = gw(request)
    out = _policy_summary(g)
    h = await judge_health(g)
    if h is not None:
        out["judge"]["healthy"] = h["healthy"]
        out["judge"]["health"] = h["detail"]
    return out


class PolicyEdit(BaseModel):
    source: str
    expected_version: str | None = None


@router.post("/api/policy/validate")
async def policy_validate(request: Request, body: PolicyEdit) -> dict[str, Any]:
    from bouncer.policy.compiled import policy_hash
    from bouncer.policy.loader import PolicyError, parse_policy

    try:
        doc = parse_policy(body.source)
    except PolicyError as exc:
        return {"ok": False, "error": _error_shape(exc.to_dict())}
    return {"ok": True, "version": policy_hash(body.source), "profile": doc.profile, "mode": doc.defaults.mode}


@router.put("/api/policy")
async def policy_save(request: Request, body: PolicyEdit) -> Any:
    """Validate, then write the policy file atomically; the normal reload path applies it."""
    import os
    import tempfile

    from bouncer.policy.loader import PolicyError, parse_policy

    g = gw(request)
    current = g.policies.current
    if body.expected_version and body.expected_version != current.version:
        return JSONResponse(
            {"error": {"type": "conflict", "message": f"The policy changed since you opened it (now {current.version}). Reload the page and apply your edit again."}},
            status_code=409,
        )
    try:
        parse_policy(body.source)
    except PolicyError as exc:
        return JSONResponse({"ok": False, "error": _error_shape(exc.to_dict())}, status_code=422)
    path = g.policies.path
    fd, tmp = tempfile.mkstemp(prefix=".bouncer-", suffix=".yaml", dir=str(path.parent))
    with os.fdopen(fd, "w") as fh:
        fh.write(body.source)
    os.replace(tmp, path)
    changed = g.policies.reload()
    return {"ok": g.policies.last_error is None, "changed": changed, "version": g.policies.current.version, "error": _error_shape(g.policies.last_error) if g.policies.last_error else None}


def _error_shape(err: dict[str, Any]) -> dict[str, Any]:
    return {k: err.get(k) for k in ("message", "path", "line", "column", "value", "snippet")}


@router.get("/api/policy/versions")
async def policy_versions(request: Request) -> dict[str, Any]:
    g = gw(request)
    out = []
    for rej in g.policies.rejected:
        where = f"{rej.get('path')} = {rej.get('value')}" if rej.get("path") else rej["message"]
        out.append(
            {
                "version": rej.get("attempted_version"),
                "loaded_at": _iso(rej["at"]),
                "status": "rejected",
                "profile": None,
                "mode": None,
                "summary": f"rejected: {where}" + (f" (line {rej['line']})" if rej.get("line") else ""),
                "error": _error_shape(rej),
                "diff": rej.get("diff"),
                "source": rej.get("text"),
                "previous_version": rej.get("active_version"),
                "path": str(g.policies.path),
            }
        )
    versions = g.policies.versions()
    for i, v in enumerate(versions):
        prev = versions[i + 1]["version"] if i + 1 < len(versions) else None
        diff = v["diff_from_previous"]
        out.append(
            {
                "version": v["version"],
                "loaded_at": _iso(v["loaded_at"]),
                "status": "active" if v["active"] else "superseded",
                "profile": v["profile"],
                "mode": v["mode"],
                "summary": _diff_summary(diff) if diff else "initial load",
                "error": None,
                "diff": diff,
                "source": next((h.text for h in g.policies.history if h.version == v["version"]), None),
                "previous_version": prev,
                "path": str(g.policies.path),
            }
        )
    out.sort(key=lambda v: v["loaded_at"] or "", reverse=True)
    return {"versions": out[:20]}


def _diff_summary(diff: str) -> str:
    changed = [ln[1:].strip() for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++") and ln[1:].strip() and not ln[1:].strip().startswith("#")]
    if not changed:
        return "Comments or formatting changed"
    head = "; ".join(changed[:3])
    return head + (f" (+{len(changed) - 3} more)" if len(changed) > 3 else "")


# ---------------------------------------------------------------------------- budgets and perf


@router.get("/api/budgets")
async def budgets(request: Request) -> dict[str, Any]:
    g = gw(request)
    doc = g.policies.current.doc
    b = doc.budgets
    today = datetime.now(UTC).date()
    teams = []
    if b is not None:
        for team, tb in b.teams.items():
            spent = g.store.team_spend_today(team)
            tpm = g.store.tokens_last_minute(team)
            gpu = g.store.gpu_seconds_last_hour(team)
            state = "ok"
            if tb.usd_per_day is not None and spent >= tb.usd_per_day:
                # what happens to the next paid request: downgraded to the local model, or blocked
                state = "downgraded" if (b.on_exceed.action == "downgrade" and b.on_exceed.downgrade_to) else "blocked"
            elif tb.usd_per_day and spent >= 0.8 * tb.usd_per_day:
                state = "warning"
            teams.append(
                {
                    "team": team,
                    "usd_per_day": tb.usd_per_day,
                    "spent_usd": round(spent, 6),
                    "requests": g.store.team_requests.get(team, 0),
                    "tokens_per_minute": tb.tokens_per_minute,
                    "tokens_last_minute": tpm,
                    "gpu_seconds_per_hour": tb.gpu_seconds_per_hour,
                    "gpu_seconds_last_hour": round(gpu, 2),
                    "state": state,
                }
            )
    per_principal: dict[str, dict[str, Any]] = {}
    day_start = datetime.combine(today, datetime.min.time(), tzinfo=UTC).timestamp()
    for ev in _events(g, None, 100000):
        if event_epoch(ev) < day_start:
            continue
        p = ev.get("principal") or {}
        pid = p.get("id")
        if not pid or pid == "anonymous":
            continue
        row = per_principal.setdefault(pid, {"principal": pid, "team": p.get("team"), "spent_usd": 0.0, "requests": 0})
        row["spent_usd"] = round(row["spent_usd"] + float((ev.get("usage") or {}).get("cost_usd") or 0), 6)
        row["requests"] += 1
    return {
        "date": today.isoformat(),
        "currency": "USD",
        "resets_at": now_iso(datetime.combine(today + timedelta(days=1), datetime.min.time(), tzinfo=UTC).timestamp()),
        "on_exceed": b.on_exceed.model_dump() if b else None,
        "teams": teams,
        "principals": sorted(per_principal.values(), key=lambda r: -r["spent_usd"]),
        "note": "Prices for commercial-mock models are illustrative; no paid API is called.",
    }


LAYER_LABELS = {"t0": "T0 deterministic", "t1": "T1 classifier", "t2": "T2 judge", "upstream": "Upstream model", "gateway_overhead": "Gateway overhead", "total": "Total"}


@router.get("/api/perf")
async def perf(request: Request, window: str = "24h") -> dict[str, Any]:
    g = gw(request)
    secs = WINDOWS.get(window, 86400)
    since = time.time() - secs
    layer_stats = g.telemetry.layer_stats(since)
    layers = []
    for layer in ("t0", "t1", "t2", "gateway_overhead", "upstream", "total"):
        s = layer_stats.get(layer) or {}
        layers.append(
            {
                "layer": layer,
                "label": LAYER_LABELS[layer],
                "n": s.get("count", 0),
                "p50": s.get("p50"),
                "p95": s.get("p95"),
                "p99": s.get("p99"),
                "max": s.get("max"),
                "histogram": [{"lo_ms": h["gt_ms"], "hi_ms": h["le_ms"], "count": h["count"]} for h in s.get("histogram", [])],
            }
        )
    evs = _events(g, secs)
    by_reason: Counter = Counter()
    escalations = cache_hits = timeouts = 0
    frags = 0
    for ev in evs:
        frags += len(ev.get("t1") or [])
        j = ev.get("judge") or {}
        if j.get("invoked"):
            escalations += 1
            by_reason[j.get("reason") or "unknown"] += 1
            cache_hits += 1 if j.get("cached") else 0
            timeouts += 1 if j.get("error") == "timeout" else 0
    n = len(evs)
    st = g.store
    lookups = st.scan_cache_hits + st.scan_cache_misses
    bucket = max(60, secs // 24)
    series_counts: Counter = Counter()
    for ev in evs:
        series_counts[int((event_epoch(ev) - since) // bucket)] += 1
    series = [{"ts": now_iso(since + i * bucket), "rps": round(series_counts.get(i, 0) / bucket, 4)} for i in range(int(secs // bucket))]
    return {
        "window": window,
        "generated_at": now_iso(),
        "requests": n,
        "throughput_rps": {
            "current": g.telemetry.throughput(60),
            "peak": max((s["rps"] for s in series), default=0.0),
            "mean": round(n / secs, 4),
            "bucket_seconds": bucket,
            "series": series,
        },
        "layers": layers,
        "t1": {"fragments_scanned": frags, "cache_hit_rate": round(st.scan_cache_hits / lookups, 4) if lookups else 0.0, "batch_size_p50": None},
        "t2": {
            "backend": g.judge.backend,
            "escalations": escalations,
            "escalation_rate": round(escalations / n, 4) if n else 0.0,
            "by_reason": dict(by_reason),
            "cache_hits": cache_hits,
            "cache_hit_rate": round(cache_hits / escalations, 4) if escalations else 0.0,
            "timeouts": timeouts,
            "fail_mode": g.policies.current.doc.defaults.fail_mode,
        },
    }


# ---------------------------------------------------------------------------- signatures and approvals


@router.get("/api/signatures")
async def signatures(request: Request) -> Any:
    g = gw(request)
    fs = g.feed_store
    if fs is None or not hasattr(fs, "status"):
        return {"feed": None, "verified": False, "signatures": [], "last_error": "signature feed not loaded (controls.signatures disabled or unavailable)"}
    st = fs.status()
    return st


def _approval_dict(appr: Any, g: Any) -> dict[str, Any]:
    d = appr.to_dict()
    ev = g.audit.get(appr.trace_id) or {}
    try:
        args = json.loads(appr.arguments_masked) if appr.arguments_masked.startswith("{") else appr.arguments_masked
    except json.JSONDecodeError:
        args = appr.arguments_masked
    findings = [f for f in ev.get("findings", []) if f.get("id") in appr.finding_ids]
    return {
        "id": appr.id,
        "status": appr.status,
        "created_at": _iso(appr.created_at),
        "expires_at": _iso(appr.expires_at),
        "trace_id": appr.trace_id,
        "principal": {"id": appr.principal, "team": appr.team},
        "session_id": appr.session_id,
        "route": ev.get("route"),
        "tool": appr.tool,
        "arguments": args,
        "arguments_hash": "sha256:" + appr.call_hash,
        "finding": appr.finding_ids[0] if appr.finding_ids else None,
        "findings": appr.finding_ids,
        "reason": appr.reason,
        "owasp_llm": sorted({o for f in findings for o in f.get("owasp_llm", [])}),
        "owasp_agentic": sorted({o for f in findings for o in f.get("owasp_agentic", [])}),
        "decided_at": _iso(appr.decided_at),
        "decided_by": "dashboard" if appr.decided_at else None,
        "note": d.get("note"),
        "allow_until": _iso(appr.allow_until),
    }


@router.get("/api/approvals")
async def approvals(request: Request, status: str | None = None) -> dict[str, Any]:
    g = gw(request)
    return {"approvals": [_approval_dict(a, g) for a in g.store.list_approvals(status)]}


@router.get("/api/approvals/{approval_id}")
async def approval_detail(request: Request, approval_id: str) -> Any:
    g = gw(request)
    for appr in g.store.list_approvals():
        if appr.id == approval_id:
            return _approval_dict(appr, g)
    return JSONResponse({"error": {"type": "not_found", "message": f"No approval {approval_id}"}}, status_code=404)


class ApprovalDecision(BaseModel):
    decision: str
    note: str | None = None


@router.post("/api/approvals/{approval_id}")
async def decide_approval(request: Request, approval_id: str, body: ApprovalDecision) -> Any:
    g = gw(request)
    if body.decision not in ("approve", "deny"):
        return JSONResponse({"error": {"type": "invalid_request", "code": "approvals.invalid_decision", "message": "decision must be approve or deny"}}, status_code=422)
    existing = next((a for a in g.store.list_approvals() if a.id == approval_id), None)
    if existing is None:
        return JSONResponse({"error": {"type": "not_found", "code": "approvals.not_found", "message": f"No approval {approval_id}"}}, status_code=404)
    if existing.status != "pending":
        return JSONResponse(
            {"error": {"type": "conflict", "code": "approvals.already_decided", "message": f"Approval {approval_id} is already {existing.status}.", "approval": _approval_dict(existing, g)}},
            status_code=409,
        )
    appr = g.store.decide_approval(approval_id, body.decision, body.note, g.policies.current.doc.approvals.ttl_seconds)
    g.audit.write(
        {
            "type": "approval.decided",
            "trace_id": appr.trace_id,
            "approval_id": appr.id,
            "decision": appr.status,
            "principal": {"id": appr.principal, "team": appr.team},
            "tool": appr.tool,
            "note": body.note,
        }
    )
    return {"approval": _approval_dict(appr, g)}


# ---------------------------------------------------------------------------- playground, scenarios, self-test


class PlaygroundIn(BaseModel):
    principal: str = "playground"
    model: str | None = None
    prompt: str | None = None
    system: str | None = None
    untrusted_tool_result: str | None = None
    tool_name: str | None = None
    messages: list[dict[str, Any]] | None = None
    session_id: str | None = None


@router.post("/api/playground")
async def playground(request: Request, body: PlaygroundIn) -> Any:
    g = gw(request)
    principal = g.policies.current.principal(body.principal)
    if principal is None:
        return JSONResponse({"error": {"type": "invalid_request", "message": f"Unknown principal {body.principal}"}}, status_code=400)
    messages = body.messages
    if not messages:
        messages = []
        if body.system:
            messages.append({"role": "system", "content": body.system})
        messages.append({"role": "user", "content": body.prompt or ""})
        if body.untrusted_tool_result:
            tool = (body.tool_name or "web.fetch").replace(".", "__")
            messages.append({"role": "assistant", "content": None, "tool_calls": [{"id": "pg_fetch", "type": "function", "function": {"name": tool, "arguments": json.dumps({"url": "https://vendor.example/playground"})}}]})
            messages.append({"role": "tool", "tool_call_id": "pg_fetch", "content": body.untrusted_tool_result})
    model = body.model or (principal.models[0] if principal.models else None)
    req = {"model": model, "messages": messages}
    t = time.perf_counter()
    principal.via = "dashboard-playground"  # audited as playground traffic, not as the agent's own calls
    resp = await handle_chat(g, principal, req, body.session_id or f"pg_{int(time.time() * 1000)}", route="playground")
    elapsed = (time.perf_counter() - t) * 1000
    trace_id = resp.headers.get("x-bouncer-trace-id")
    payload = json.loads(resp.body) if hasattr(resp, "body") else {}
    ev = g.audit.get(trace_id) if trace_id else None
    reply = None
    block = None
    if resp.status_code == 200 and "choices" in payload:
        reply = (payload["choices"][0].get("message") or {}).get("content")
        tcs = (payload["choices"][0].get("message") or {}).get("tool_calls")
        if tcs and not reply:
            reply = "Tool calls: " + ", ".join(f"{tc['function']['name']}({tc['function']['arguments']})" for tc in tcs)
    elif "error" in payload:
        block = payload["error"]
    return {
        "trace_id": trace_id,
        "action": (ev or {}).get("action") or resp.headers.get("x-bouncer-action"),
        "status_code": resp.status_code,
        "reply": reply,
        "block": block,
        "upstream_called": bool((ev or {}).get("latency_ms", {}).get("upstream")),
        "latency_ms": round(elapsed, 2),
        "events": [ev] if ev else [],
    }


def _scenario_files() -> list[Path]:
    return sorted((ROOT / "demo" / "scenarios").glob("*.yaml"))


@router.get("/api/scenarios")
async def scenarios(request: Request) -> dict[str, Any]:
    out = []
    for path in _scenario_files():
        try:
            sc = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError:
            continue
        if not isinstance(sc, dict) or "id" not in sc:
            continue
        outcome = (sc.get("expect") or {}).get("outcome")
        expected = " or ".join(outcome) if isinstance(outcome, list) else outcome
        out.append({"id": sc["id"], "title": sc.get("title", sc["id"]), "description": sc.get("description", ""), "principal": sc.get("principal"), "kind": sc.get("kind", "openai"), "expected_action": expected})
    return {"mode": "scripted", "scenarios": out}


@router.post("/api/scenarios/{scenario_id}/run")
async def run_scenario(request: Request, scenario_id: str) -> Any:
    from bouncer.gateway.scenarios import run_scenario_file

    g = gw(request)
    for path in _scenario_files():
        sc = yaml.safe_load(path.read_text()) or {}
        if isinstance(sc, dict) and sc.get("id") == scenario_id:
            return await run_scenario_file(g, sc)
    return JSONResponse({"error": {"type": "not_found", "message": f"No scenario {scenario_id} in demo/scenarios/"}}, status_code=404)


@router.post("/api/selftest")
async def selftest(request: Request) -> dict[str, Any]:
    from bouncer.selftest import run_selftest

    started = now_iso()
    t = time.perf_counter()
    res = await asyncio.get_running_loop().run_in_executor(None, run_selftest)
    out = {
        "started_at": started,
        "duration_ms": round((time.perf_counter() - t) * 1000),
        "mode": "offline",
        "command": "make test (YAML cases only; unit tests run with make test)",
        "total": res["total"],
        "passed": res["passed"],
        "failed": res["failed"],
        "skipped": 0,
        "by_control": [{"control": c, "total": v["total"], "passed": v["passed"], "failed": v["failed"], "allow_cases": v["allow"], "block_cases": v["block"]} for c, v in sorted(res["by_control"].items())],
        "failures": [
            {"id": f["id"], "control": f["control"], "kind": f["kind"], "expected": f["kind"], "got": ",".join(f["actions"]), "message": "; ".join(f["failures"])[:500]}
            for f in res["failures"]
        ],
        "report_url": None,
    }
    request.app.state.last_selftest = out
    return out


# ---------------------------------------------------------------------------- exports and report


def _export_filters(request: Request) -> dict[str, Any]:
    """Events-view filters plus optional from/to (ISO timestamps) for the exports."""
    q = request.query_params
    out: dict[str, Any] = {**_filter_params(request), "since_ts": None, "until_ts": None}
    for key, target in (("from", "since_ts"), ("to", "until_ts")):
        if q.get(key):
            out[target] = event_epoch({"ts": q[key].replace("Z", "+00:00")})
            if not out[target]:
                raise ValueError(f"'{key}' must be an ISO 8601 timestamp, for example 2026-10-04T08:00:00Z.")
    return out


def _bad_export(exc: ValueError) -> JSONResponse:
    return JSONResponse({"error": {"type": "invalid_request", "code": "export.bad_timestamp", "message": str(exc)}}, status_code=422)


def _export_name(ext: str) -> str:
    return f"bouncer-audit-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.{ext}"


@router.get("/api/export/audit.jsonl")
async def export_jsonl(request: Request) -> Any:
    """The whole matching log, oldest first, lines unchanged (an unfiltered export passes make verify-audit)."""
    g = gw(request)
    try:
        filters = _export_filters(request)
    except ValueError as exc:
        return _bad_export(exc)
    lines = (line for line, _ in g.audit.export(**filters))
    return StreamingResponse(lines, media_type="application/x-ndjson", headers={"Content-Disposition": f'attachment; filename="{_export_name("jsonl")}"'})


@router.get("/api/export/audit.csv")
async def export_csv(request: Request) -> Any:
    """The whole matching log as CSV with the columns of docs/API.md section 5."""
    g = gw(request)
    try:
        filters = _export_filters(request)
    except ValueError as exc:
        return _bad_export(exc)

    def body() -> Iterator[str]:
        yield csv_header()
        for _, ev in g.audit.export(**filters):
            yield csv_line(ev)

    return StreamingResponse(body(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{_export_name("csv")}"'})


@router.get("/reports/summary")
async def report_summary(request: Request, window: str = "24h") -> HTMLResponse:
    from bouncer.gateway.report import render_summary

    s = await stats(request, window)
    cov = await coverage(request)
    bud = await budgets(request)
    pol = _policy_summary(gw(request))
    return HTMLResponse(render_summary(s, cov, bud, pol))
