"""Tamper-evident audit log: one JSON line per decision, chained with SHA-256.

hash = sha256(prev_hash + canonical_json(event without "hash")). Deleting, reordering or editing a
line breaks the chain from that point; `make verify-audit` reports the first broken line.
Only post-redaction excerpts and masked evidence are ever written here.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import os
import threading
import time
from collections import deque
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical(event: dict[str, Any]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def chain_hash(prev_hash: str, event: dict[str, Any]) -> str:
    body = {k: v for k, v in event.items() if k != "hash"}
    return hashlib.sha256(prev_hash.encode() + canonical(body)).hexdigest()


def event_epoch(ev: dict[str, Any]) -> float:
    try:
        return datetime.fromisoformat(str(ev.get("ts"))).timestamp()
    except ValueError:
        return 0.0


def now_iso(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(ts if ts is not None else time.time(), tz=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class AuditLog:
    def __init__(self, path: str | Path | None, hash_chain: bool = True, memory_size: int = 5000) -> None:
        self.path = Path(path) if path else None
        self.hash_chain = hash_chain
        self.events: deque[dict[str, Any]] = deque(maxlen=memory_size)
        self.by_trace: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._subscribers: set[asyncio.Queue] = set()
        self.seq = 0
        self.prev_hash = GENESIS
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._resume()

    def _resume(self) -> None:
        """Continue the chain from the last line of an existing log and warm the in-memory buffer."""
        if not self.path or not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self.seq = max(self.seq, int(ev.get("seq", 0)))
                self.prev_hash = ev.get("hash", self.prev_hash)
                self._remember(ev)

    def _remember(self, ev: dict[str, Any]) -> None:
        if len(self.events) == self.events.maxlen:
            old = self.events[0]
            bucket = self.by_trace.get(old.get("trace_id", ""))
            if bucket and old in bucket:
                bucket.remove(old)
                if not bucket:
                    self.by_trace.pop(old.get("trace_id", ""), None)
        self.events.append(ev)
        if ev.get("trace_id"):
            # several events can share a trace id (the decision, then approval.decided)
            self.by_trace.setdefault(ev["trace_id"], []).append(ev)

    def write(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.seq += 1
            ev = {"ts": now_iso(), "seq": self.seq, **event}
            ev["seq"] = self.seq
            ev["prev_hash"] = self.prev_hash
            ev["hash"] = chain_hash(self.prev_hash, ev) if self.hash_chain else ""
            self.prev_hash = ev["hash"] or self.prev_hash
            if self.path:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(ev, ensure_ascii=False, default=str) + "\n")
                    if os.environ.get("BOUNCER_AUDIT_FSYNC") == "1":
                        fh.flush()
                        os.fsync(fh.fileno())
            self._remember(ev)
            if self.path:
                # sidecar with the newest seq and hash: lines removed from the end of the log are detectable
                head = self.path.with_name(self.path.name + ".head")
                tmp = head.with_name(head.name + ".tmp")
                tmp.write_text(json.dumps({"seq": ev["seq"], "hash": ev["hash"]}))
                os.replace(tmp, head)
        for q in list(self._subscribers):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                pass
        return ev

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def get(self, trace_id: str) -> dict[str, Any] | None:
        """The decision event of a trace (or the first event when there is no decision)."""
        bucket = self.by_trace.get(trace_id) or []
        for ev in bucket:
            if ev.get("type", "decision") == "decision":
                return ev
        return bucket[0] if bucket else None

    def trace(self, trace_id: str) -> list[dict[str, Any]]:
        """All events of a trace, decision first."""
        bucket = list(self.by_trace.get(trace_id) or [])
        return sorted(bucket, key=lambda e: (e.get("type", "decision") != "decision", e.get("seq", 0)))

    def query(
        self,
        action: str | None = None,
        control: str | None = None,
        principal: str | None = None,
        route: str | None = None,
        q: str | None = None,
        limit: int = 100,
        before_seq: int | None = None,
        since_ts: float | None = None,
        kind: str | None = "decision",
    ) -> list[dict[str, Any]]:
        out = []
        for ev in reversed(self.events):
            if before_seq is not None and ev.get("seq", 0) >= before_seq:
                continue
            if not matches(ev, action=action, control=control, principal=principal, route=route, q=q, since_ts=since_ts, kind=kind):
                continue
            out.append(ev)
            if len(out) >= limit:
                break
        return out

    def export(self, until_ts: float | None = None, **filters: Any) -> Iterator[tuple[str, dict[str, Any]]]:
        """(line, event) pairs of the whole log, oldest first, that match the filters of query().

        Reads the file, not the in-memory buffer, so an export covers the full history; the line is
        returned unchanged so that an unfiltered JSONL export still passes `make verify-audit`.
        """
        if self.path and self.path.exists():
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if matches(ev, until_ts=until_ts, **filters):
                        yield (line if line.endswith("\n") else line + "\n"), ev
            return
        for ev in list(self.events):
            if matches(ev, until_ts=until_ts, **filters):
                yield json.dumps(ev, ensure_ascii=False, default=str) + "\n", ev


def matches(
    ev: dict[str, Any],
    action: str | None = None,
    control: str | None = None,
    principal: str | None = None,
    route: str | None = None,
    q: str | None = None,
    since_ts: float | None = None,
    until_ts: float | None = None,
    kind: str | None = None,
) -> bool:
    """The event filters of the Events view and the exports."""
    if kind and ev.get("type", "decision") != kind:
        return False
    if since_ts is not None and event_epoch(ev) < since_ts:
        return False
    if until_ts is not None and event_epoch(ev) > until_ts:
        return False
    if action and ev.get("action") != action:
        return False
    if principal and (ev.get("principal") or {}).get("id") != principal:
        return False
    if route and ev.get("route") != route:
        return False
    if control and not any(
        f.get("control") == control or f.get("id", "").startswith(control) for f in ev.get("findings", [])
    ):
        return False
    return not (q and q.lower() not in json.dumps(ev, ensure_ascii=False, default=str).lower())


# docs/API.md section 5
CSV_FIELDS = [
    "ts", "seq", "trace_id", "type", "principal", "team", "session_id", "route", "direction", "model", "upstream",
    "action", "enforced", "status_code", "top_finding", "findings", "owasp", "judge_invoked", "latency_total_ms",
    "gateway_overhead_ms", "cost_usd", "policy_version", "approval_id", "excerpt", "prev_hash", "hash",
]

_ACTION_RANK = {"allow": 0, "log": 1, "redact": 2, "require_approval": 3, "block": 4}
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _cell(value: Any) -> Any:
    """Neutralize spreadsheet formulas: audit text is attacker-controlled (prompts, tool output)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def top_finding(findings: list[dict[str, Any]]) -> str | None:
    """Strongest action first, then highest severity, then highest score."""
    if not findings:
        return None
    best = max(findings, key=lambda f: (
        _ACTION_RANK.get(str(f.get("effective_action") or f.get("action")), 0),
        _SEVERITY_RANK.get(str(f.get("severity")), 0),
        float(f.get("score") or 0),
    ))
    return best.get("id")


def csv_row(ev: dict[str, Any]) -> dict[str, Any]:
    p = ev.get("principal") or {}
    lat = ev.get("latency_ms") or {}
    findings = ev.get("findings") or []
    owasp = sorted({o for f in findings for o in (f.get("owasp_llm") or []) + (f.get("owasp_agentic") or [])})
    row = {
        "ts": ev.get("ts"),
        "seq": ev.get("seq"),
        "trace_id": ev.get("trace_id"),
        "type": ev.get("type", "decision"),
        "principal": p.get("id") if isinstance(p, dict) else p,
        "team": p.get("team") if isinstance(p, dict) else None,
        "session_id": ev.get("session_id"),
        "route": ev.get("route"),
        "direction": ev.get("direction"),
        "model": ev.get("model"),
        "upstream": ev.get("upstream"),
        "action": ev.get("action"),
        "enforced": ev.get("enforced"),
        "status_code": ev.get("status_code"),
        "top_finding": top_finding(findings),
        "findings": ";".join(f.get("id", "") for f in findings),
        "owasp": ";".join(owasp),
        "judge_invoked": (ev.get("judge") or {}).get("invoked") if "judge" in ev else None,
        "latency_total_ms": lat.get("total"),
        "gateway_overhead_ms": lat.get("gateway_overhead"),
        "cost_usd": (ev.get("usage") or {}).get("cost_usd"),
        "policy_version": (ev.get("policy") or {}).get("version"),
        "approval_id": ev.get("approval_id"),
        "excerpt": ev.get("excerpt"),
        "prev_hash": ev.get("prev_hash"),
        "hash": ev.get("hash"),
    }
    return {k: ("" if v is None else _cell(v)) for k, v in row.items()}


def csv_header() -> str:
    buf = io.StringIO()
    csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\r\n").writeheader()
    return buf.getvalue()


def csv_line(ev: dict[str, Any]) -> str:
    buf = io.StringIO()
    csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\r\n").writerow(csv_row(ev))
    return buf.getvalue()


def to_csv(events: list[dict[str, Any]]) -> str:
    """RFC 4180 CSV (CRLF line ends) with the columns of docs/API.md section 5."""
    return csv_header() + "".join(csv_line(ev) for ev in events)


# OCSF 1.3.0 Detection Finding (class_uid 2004) with the security_control profile; enum values checked
# against https://schema.ocsf.io/api/1.3.0/classes/detection_finding.
OCSF_VERSION = "1.3.0"
_OCSF_SEVERITY = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_OCSF_SEVERITY_NAME = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
# action -> (action_id, action, disposition_id, disposition)
_OCSF_ACTION = {
    "allow": (1, "Allowed", 1, "Allowed"),
    "log": (1, "Allowed", 17, "Logged"),
    "redact": (1, "Allowed", 99, "Redacted"),
    "require_approval": (2, "Denied", 14, "Delayed"),
    "block": (2, "Denied", 2, "Blocked"),
}


def to_ocsf(ev: dict[str, Any], product_version: str = "0.1.0") -> dict[str, Any]:
    """One audit event as an OCSF Detection Finding. Bouncer-specific fields go to `unmapped.bouncer`."""
    findings = ev.get("findings") or []
    sev = max((_OCSF_SEVERITY.get(str(f.get("severity")), 0) for f in findings), default=1) or 1
    action = str(ev.get("action") or ("block" if ev.get("type") in ("policy.reload_failed", "feed.rejected") else "allow"))
    action_id, action_name, disp_id, disp = _OCSF_ACTION.get(action, (0, "Unknown", 0, "Unknown"))
    top = top_finding(findings)
    kind = ev.get("type", "decision")
    title = top or (kind if kind != "decision" else f"Request {action_name.lower()}")
    principal = ev.get("principal") or {}
    owasp = sorted({o for f in findings for o in (f.get("owasp_llm") or []) + (f.get("owasp_agentic") or [])})
    atlas = sorted({a for f in findings for a in (f.get("atlas") or [])})
    t = int(event_epoch(ev) * 1000)
    return {
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "type_name": "Detection Finding: Create",
        "time": t,
        "severity_id": sev,
        "severity": _OCSF_SEVERITY_NAME[sev],
        "status_id": 1,
        "status": "New",
        "action_id": action_id,
        "action": action_name,
        "disposition_id": disp_id,
        "disposition": disp,
        "message": ev.get("message") or next((f.get("message") for f in findings if f.get("id") == top), None) or title,
        "finding_info": {
            "uid": ev.get("trace_id") or f"seq-{ev.get('seq')}",
            "title": title,
            "types": [f.get("id") for f in findings if f.get("id")] or [kind],
            "created_time": t,
        },
        "metadata": {
            "version": OCSF_VERSION,
            "profiles": ["security_control"],
            "product": {"name": "Bouncer", "vendor_name": "Bouncer", "version": product_version},
            "log_name": "audit",
            "uid": ev.get("hash"),
            "original_time": ev.get("ts"),
        },
        "unmapped": {
            "bouncer": {
                "type": kind,
                "seq": ev.get("seq"),
                "principal": principal.get("id") if isinstance(principal, dict) else principal,
                "team": principal.get("team") if isinstance(principal, dict) else None,
                "session_id": ev.get("session_id"),
                "route": ev.get("route"),
                "direction": ev.get("direction"),
                "model": ev.get("model"),
                "upstream": ev.get("upstream"),
                "enforced": ev.get("enforced"),
                "status_code": ev.get("status_code"),
                "policy_version": (ev.get("policy") or {}).get("version"),
                "approval_id": ev.get("approval_id"),
                "owasp": owasp,
                "mitre_atlas": atlas,
                "findings": [
                    {k: f.get(k) for k in ("id", "action", "effective_action", "severity", "score", "tier", "message", "evidence", "signature_id")}
                    for f in findings
                ],
                "judge_invoked": (ev.get("judge") or {}).get("invoked"),
                "latency_ms": ev.get("latency_ms"),
                "cost_usd": (ev.get("usage") or {}).get("cost_usd"),
                "excerpt": ev.get("excerpt"),
                "prev_hash": ev.get("prev_hash"),
                "hash": ev.get("hash"),
            }
        },
    }


def verify_file(path: str | Path) -> dict[str, Any]:
    """Verify the hash chain of an audit file. Returns ok, lines checked and the first problem."""
    prev = GENESIS
    expected_seq = None
    checked = 0
    with Path(path).open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as exc:
                return {"ok": False, "checked": checked, "line": lineno, "error": f"invalid JSON: {exc}"}
            if ev.get("prev_hash") != prev:
                return {
                    "ok": False,
                    "checked": checked,
                    "line": lineno,
                    "seq": ev.get("seq"),
                    "error": "prev_hash does not match the previous line: a line was deleted, inserted or reordered",
                }
            if chain_hash(prev, ev) != ev.get("hash"):
                return {
                    "ok": False,
                    "checked": checked,
                    "line": lineno,
                    "seq": ev.get("seq"),
                    "error": "hash mismatch: this line was modified after it was written",
                }
            if expected_seq is not None and ev.get("seq") != expected_seq:
                return {"ok": False, "checked": checked, "line": lineno, "error": "sequence gap"}
            expected_seq = ev.get("seq", 0) + 1
            prev = ev["hash"]
            checked += 1
    head = Path(path).with_name(Path(path).name + ".head")
    if head.exists():
        try:
            h = json.loads(head.read_text())
        except (OSError, json.JSONDecodeError):
            h = {}
        if h.get("hash") and h.get("hash") != prev:
            return {
                "ok": False,
                "checked": checked,
                "line": checked + 1,
                "seq": h.get("seq"),
                "error": f"the log ends at seq {expected_seq - 1 if expected_seq else 0} but the head record says seq {h.get('seq')}: lines were removed from the end",
            }
    return {"ok": True, "checked": checked, "last_hash": prev}
