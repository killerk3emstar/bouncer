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
        self.by_trace: dict[str, dict[str, Any]] = {}
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
            self.by_trace.pop(old.get("trace_id", ""), None)
        self.events.append(ev)
        if ev.get("trace_id"):
            self.by_trace[ev["trace_id"]] = ev

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
        return self.by_trace.get(trace_id)

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
        ql = q.lower() if q else None
        for ev in reversed(self.events):
            if kind and ev.get("kind", "decision") != kind:
                continue
            if before_seq is not None and ev.get("seq", 0) >= before_seq:
                continue
            if since_ts is not None and event_epoch(ev) < since_ts:
                continue
            if action and ev.get("action") != action:
                continue
            if principal and (ev.get("principal") or {}).get("id") != principal:
                continue
            if route and ev.get("route") != route:
                continue
            if control and not any(
                f.get("control") == control or f.get("id", "").startswith(control) for f in ev.get("findings", [])
            ):
                continue
            if ql and ql not in json.dumps(ev, ensure_ascii=False, default=str).lower():
                continue
            out.append(ev)
            if len(out) >= limit:
                break
        return out


CSV_FIELDS = [
    "ts", "seq", "trace_id", "principal", "team", "session_id", "route", "direction", "model", "action",
    "findings", "latency_ms_total", "cost_usd", "policy_version", "excerpt", "hash",
]


def to_csv(events: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS)
    w.writeheader()
    for ev in events:
        p = ev.get("principal") or {}
        lat = ev.get("latency_ms") or {}
        w.writerow(
            {
                "ts": ev.get("ts"),
                "seq": ev.get("seq"),
                "trace_id": ev.get("trace_id"),
                "principal": p.get("id"),
                "team": p.get("team"),
                "session_id": ev.get("session_id"),
                "route": ev.get("route"),
                "direction": ev.get("direction"),
                "model": ev.get("model"),
                "action": ev.get("action"),
                "findings": ";".join(f.get("id", "") for f in ev.get("findings", [])),
                "latency_ms_total": lat.get("total"),
                "cost_usd": (ev.get("usage") or {}).get("cost_usd"),
                "policy_version": (ev.get("policy") or {}).get("version"),
                "excerpt": ev.get("excerpt"),
                "hash": ev.get("hash"),
            }
        )
    return buf.getvalue()


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
    return {"ok": True, "checked": checked, "last_hash": prev}
