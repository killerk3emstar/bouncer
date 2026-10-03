"""Helpers for OpenAI chat payloads: segment extraction, write-back, tool name mapping, token estimates."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from bouncer.core import Segment


def norm_tool(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def resolve_tool_name(wire_name: str, known: list[str] | set[str]) -> str:
    """Map a wire function name (OpenAI names cannot contain dots, so agents send crm_lookup_customer
    or crm__lookup_customer) to the dotted policy name (crm.lookup_customer). Unknown names are
    returned unchanged."""
    if wire_name in known:
        return wire_name
    target = norm_tool(wire_name)
    for k in known:
        if norm_tool(k) == target:
            return k
    return wire_name


def content_parts(content: Any) -> list[tuple[tuple[Any, ...], str]]:
    """Return (relative location, text) for a message content (string or list of parts)."""
    if content is None:
        return []
    if isinstance(content, str):
        return [(("content",), content)]
    out = []
    if isinstance(content, list):
        for j, part in enumerate(content):
            # any part with a text field reaches the model as text, whatever its declared type
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                out.append((("content", j, "text"), part["text"]))
    return out


def get_in(obj: Any, location: tuple[Any, ...]) -> Any:
    for key in location:
        obj = obj[key]
    return obj


def set_in(obj: Any, location: tuple[Any, ...], value: Any) -> None:
    for key in location[:-1]:
        obj = obj[key]
    obj[location[-1]] = value


def tool_call_index(messages: list[dict[str, Any]]) -> dict[str, str]:
    """tool_call_id -> function name, from assistant messages in the history."""
    idx: dict[str, str] = {}
    for m in messages:
        if m.get("role") == "assistant":
            for tc in m.get("tool_calls") or []:
                fn = (tc.get("function") or {}).get("name")
                if tc.get("id") and fn:
                    idx[tc["id"]] = fn
    return idx


def extract_input_segments(
    body: dict[str, Any], known_tools: set[str], untrusted_tools: set[str]
) -> list[Segment]:
    segments: list[Segment] = []
    messages = body.get("messages") or []
    call_idx = tool_call_index(messages)
    for i, m in enumerate(messages):
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        parts = content_parts(m.get("content"))
        for rel, text in parts:
            loc = ("messages", i, *rel)
            if role in ("system", "developer"):
                segments.append(Segment(text, "input", "system", True, loc))
            elif role == "user":
                segments.append(Segment(text, "input", "user", False, loc))
            elif role == "assistant":
                segments.append(Segment(text, "input", "assistant", True, loc))
            elif role in ("tool", "function"):
                wire = call_idx.get(m.get("tool_call_id", ""), m.get("name") or "unknown")
                name = resolve_tool_name(wire, known_tools)
                segments.append(
                    Segment(text, "tool_result", f"tool_result:{name}", name not in untrusted_tools, loc, tool=name)
                )
    # tool calls already made (history): their arguments go back to the model, so secrets in them are redacted
    for i, m in enumerate(messages):
        if isinstance(m, dict) and m.get("role") == "assistant":
            for k, tc in enumerate(m.get("tool_calls") or []):
                fn = (tc or {}).get("function") or {}
                args = fn.get("arguments")
                if isinstance(args, str) and args:
                    name = resolve_tool_name(str(fn.get("name", "")), known_tools)
                    segments.append(Segment(args, "tool_call", f"tool_call:{name}", True, ("messages", i, "tool_calls", k, "function", "arguments"), tool=name))
    for j, f in enumerate(body.get("functions") or []):  # legacy functions API
        if isinstance(f, dict):
            name = resolve_tool_name(str(f.get("name", "")), known_tools)
            text = f"{f.get('name', '')}\n{f.get('description', '') or ''}\n{json.dumps(f.get('parameters') or {}, ensure_ascii=False)}"
            segments.append(Segment(text, "tool_definition", f"tool_definition:{name}", False, ("functions", j), tool=name))
    for j, t in enumerate(body.get("tools") or []):
        fn = (t or {}).get("function") or {}
        name = resolve_tool_name(str(fn.get("name", "")), known_tools)
        text = f"{fn.get('name', '')}\n{fn.get('description', '') or ''}\n{json.dumps(fn.get('parameters') or {}, ensure_ascii=False)}"
        segments.append(Segment(text, "tool_definition", f"tool_definition:{name}", False, ("tools", j), tool=name))
    return segments


def history_tool_results(body: dict[str, Any], known_tools: set[str]) -> list[str]:
    messages = body.get("messages") or []
    call_idx = tool_call_index(messages)
    out = []
    for m in messages:
        if isinstance(m, dict) and m.get("role") in ("tool", "function"):
            wire = call_idx.get(m.get("tool_call_id", ""), m.get("name") or "unknown")
            out.append(resolve_tool_name(wire, known_tools))
    return out


def history_tool_call_hashes(body: dict[str, Any], known_tools: set[str]) -> list[str]:
    out = []
    for m in body.get("messages") or []:
        if isinstance(m, dict) and m.get("role") == "assistant":
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                name = resolve_tool_name(str(fn.get("name", "")), known_tools)
                out.append(call_hash(name, parse_args(fn.get("arguments"))))
    return out


def last_user_text(body: dict[str, Any]) -> str:
    for m in reversed(body.get("messages") or []):
        if isinstance(m, dict) and m.get("role") == "user":
            return " ".join(t for _, t in content_parts(m.get("content")))
    return ""


def assistant_turns(body: dict[str, Any]) -> int:
    return sum(1 for m in body.get("messages") or [] if isinstance(m, dict) and m.get("role") == "assistant")


def parse_args(arguments: Any) -> Any:
    if isinstance(arguments, (dict, list)):
        return arguments
    if not arguments:
        return {}
    try:
        return json.loads(arguments)
    except (TypeError, json.JSONDecodeError):
        return {"_raw": str(arguments)}


def call_hash(tool: str, args: Any) -> str:
    canon = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(f"{tool}\n{canon}".encode()).hexdigest()[:32]


def estimate_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4) if text else 0


def request_text(body: dict[str, Any]) -> str:
    chunks = []
    for m in body.get("messages") or []:
        if isinstance(m, dict):
            chunks.extend(t for _, t in content_parts(m.get("content")))
            for tc in m.get("tool_calls") or []:
                chunks.append(str((tc.get("function") or {}).get("arguments") or ""))
    for t in body.get("tools") or []:
        chunks.append(json.dumps(t, ensure_ascii=False))
    return "\n".join(chunks)
