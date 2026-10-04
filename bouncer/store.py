"""In-memory state: budget counters, rate windows, loop detection, session taint, approvals,
scan cache and MCP tool pins.

The gateway itself is stateless per request; this store holds the counters that must be shared.
This class keeps everything in process memory (one node, the default). For several replicas,
bouncer.store_redis.RedisStore implements the same interface on Redis (BOUNCER_STORE=redis://...).
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def day_key(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), tz=UTC).strftime("%Y-%m-%d")


@dataclass
class Approval:
    id: str
    principal: str
    team: str
    session_id: str
    call_hash: str
    tool: str
    arguments_masked: str
    reason: str
    finding_ids: list[str]
    trace_id: str
    created_at: float
    expires_at: float
    status: str = "pending"  # pending | approved | denied | expired | used
    principal_key: str = ""  # principal id, or "<caller>><principal>" for a delegated call
    decided_at: float | None = None
    note: str | None = None
    allow_until: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "principal": self.principal,
            "team": self.team,
            "session_id": self.session_id,
            "tool": self.tool,
            "arguments": self.arguments_masked,
            "reason": self.reason,
            "findings": self.finding_ids,
            "trace_id": self.trace_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "decided_at": self.decided_at,
            "note": self.note,
        }


@dataclass
class SessionState:
    taint: set[str] = field(default_factory=set)  # "untrusted", "sensitive"
    taint_sources: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    steps: int = 0
    usd: float = 0.0
    tool_calls: deque = field(default_factory=lambda: deque(maxlen=200))  # (ts, call_hash)
    breaker_until: float = 0.0
    breaker_reason: str = ""
    last_seen: float = 0.0


class Store:
    shared = False  # True for a store whose counters outlive the process (Redis): no replay needed

    def __init__(self, scan_cache_size: int = 20000) -> None:
        self._lock = threading.RLock()
        self.team_usd: dict[tuple[str, str], float] = defaultdict(float)  # (team, day) -> usd
        self.team_tokens: dict[str, deque] = defaultdict(deque)  # team -> (ts, tokens)
        self.team_gpu: dict[str, deque] = defaultdict(deque)  # team -> (ts, gpu seconds)
        self.team_requests: dict[str, int] = defaultdict(int)
        self.sessions: OrderedDict[str, SessionState] = OrderedDict()
        self.max_sessions = 50_000  # oldest sessions are evicted; session ids are chosen by clients
        self.approvals: dict[str, Approval] = {}
        self.scan_cache: OrderedDict[tuple, Any] = OrderedDict()
        self.scan_cache_size = scan_cache_size
        self.scan_cache_hits = 0
        self.scan_cache_misses = 0
        self.mcp_pins: dict[str, dict[str, str]] = defaultdict(dict)  # server -> tool -> definition hash
        self.mcp_pending: dict[str, dict[str, str]] = defaultdict(dict)

    def _sess(self, session_id: str) -> SessionState:
        with self._lock:
            sess = self.sessions.get(session_id)
            if sess is None:
                sess = self.sessions[session_id] = SessionState()
                while len(self.sessions) > self.max_sessions:
                    self.sessions.popitem(last=False)
            else:
                self.sessions.move_to_end(session_id)
            return sess

    def reset(self) -> None:
        self.__init__(self.scan_cache_size)  # type: ignore[misc]

    # ------------------------------------------------------------------ budgets
    def team_spend_today(self, team: str) -> float:
        return self.team_usd.get((team, day_key()), 0.0)

    def add_spend(self, team: str, session_id: str, usd: float, tokens: int, gpu_seconds: float) -> None:
        now = time.time()
        with self._lock:
            self.team_usd[(team, day_key(now))] += usd
            self.team_tokens[team].append((now, tokens))
            if gpu_seconds:
                self.team_gpu[team].append((now, gpu_seconds))
            self._sess(session_id).usd += usd
            self.team_requests[team] += 1

    def replay_spend(self, events: Any) -> int:
        """Rebuild today's per-team and per-session spend from audit events (after a restart).

        RedisStore keeps these counters in Redis, where they survive restarts, and skips the replay."""
        today = day_key()
        n = 0
        for ev in events:
            if ev.get("type", "decision") != "decision":
                continue
            ts = str(ev.get("ts", ""))
            if not ts.startswith(today):
                continue
            usage = ev.get("usage") or {}
            team = (ev.get("principal") or {}).get("team")
            cost = float(usage.get("cost_usd") or 0)
            if team and cost:
                self.team_usd[(team, today)] += cost
                self._sess(ev.get("session_id", "")).usd += cost
            if team:
                self.team_requests[team] += 1
            n += 1
        return n

    def tokens_last_minute(self, team: str) -> int:
        return int(self._window_sum(self.team_tokens[team], 60))

    def gpu_seconds_last_hour(self, team: str) -> float:
        return self._window_sum(self.team_gpu[team], 3600)

    def _window_sum(self, dq: deque, seconds: float) -> float:
        cutoff = time.time() - seconds
        with self._lock:
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            return float(sum(v for _, v in dq))

    # ------------------------------------------------------------------ sessions
    def session(self, session_id: str) -> SessionState:
        s = self._sess(session_id)
        s.last_seen = time.time()
        return s

    def mark_taint(self, session_id: str, kind: str, source: str) -> None:
        with self._lock:
            s = self._sess(session_id)
            s.taint.add(kind)
            if source not in s.taint_sources[kind]:
                s.taint_sources[kind].append(source)

    def record_tool_call(self, session_id: str, call_hash: str) -> None:
        with self._lock:
            self._sess(session_id).tool_calls.append((time.time(), call_hash))

    def identical_calls(self, session_id: str, call_hash: str, window_seconds: float) -> int:
        cutoff = time.time() - window_seconds
        s = self._sess(session_id)
        return sum(1 for ts, h in s.tool_calls if h == call_hash and ts >= cutoff)

    # ------------------------------------------------------------------ approvals
    def create_approval(self, **kw: Any) -> Approval:
        now = time.time()
        ttl = kw.pop("ttl_seconds")
        appr = Approval(id="apr_" + secrets.token_hex(4), created_at=now, expires_at=now + ttl, **kw)
        with self._lock:
            # one pending request per identical call is enough
            for existing in self.approvals.values():
                if (
                    existing.status == "pending"
                    and existing.call_hash == appr.call_hash
                    and existing.principal == appr.principal
                    and existing.expires_at > now
                ):
                    return existing
            self.approvals[appr.id] = appr
        return appr

    def decide_approval(self, approval_id: str, decision: str, note: str | None, ttl_seconds: int) -> Approval | None:
        with self._lock:
            appr = self.approvals.get(approval_id)
            if appr is None:
                return None
            now = time.time()
            if appr.status == "pending" and appr.expires_at < now:
                appr.status = "expired"
            if appr.status != "pending":
                return appr
            appr.status = "approved" if decision == "approve" else "denied"
            appr.decided_at = now
            appr.note = note
            if appr.status == "approved":
                appr.allow_until = now + ttl_seconds
            return appr

    def approved(self, principal_key: str, call_hash: str, session_id: str | None = None) -> Approval | None:
        """An approval allows exactly one identical call, by the same agent in the same session, within its
        window. It is consumed when used."""
        now = time.time()
        with self._lock:
            for appr in self.approvals.values():
                if (
                    appr.status == "approved"
                    and (appr.principal_key or appr.principal) == principal_key
                    and appr.call_hash == call_hash
                    and (session_id is None or appr.session_id == session_id)
                    and (appr.allow_until or 0) >= now
                ):
                    appr.status = "used"
                    return appr
        return None

    def list_approvals(self, status: str | None = None) -> list[Approval]:
        now = time.time()
        out = []
        for appr in self.approvals.values():
            if appr.status == "pending" and appr.expires_at < now:
                appr.status = "expired"
            if status and appr.status != status:
                continue
            out.append(appr)
        return sorted(out, key=lambda a: a.created_at, reverse=True)

    # ------------------------------------------------------------------ scan cache
    def cache_get(self, key: tuple) -> Any | None:
        with self._lock:
            val = self.scan_cache.get(key)
            if val is None:
                self.scan_cache_misses += 1
                return None
            self.scan_cache.move_to_end(key)
            self.scan_cache_hits += 1
            return val

    def cache_put(self, key: tuple, value: Any) -> None:
        with self._lock:
            self.scan_cache[key] = value
            self.scan_cache.move_to_end(key)
            while len(self.scan_cache) > self.scan_cache_size:
                self.scan_cache.popitem(last=False)
