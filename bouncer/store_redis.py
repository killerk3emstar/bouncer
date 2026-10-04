"""Redis-backed Store, so several gateway replicas share budgets, sessions, approvals and MCP pins.

Selected with BOUNCER_STORE=redis://host:port/db (see bouncer.gateway.state.Settings). The public API and
attribute behaviour match bouncer.store.Store, so the pipeline and the gateway routes work unchanged:

- team USD per day: INCRBYFLOAT on <prefix>usd:<team>:<day>, key expires after 2 days
- tokens per minute, GPU seconds per hour: sorted sets scored by timestamp, trimmed on read and write
- request counts per team: hash <prefix>requests:<day>
- sessions: hash <prefix>sess:<id> (steps, usd, breaker_until, breaker_reason, last_seen), a set of taint
  kinds, one sorted set of sources per taint kind and a sorted set of recent tool-call hashes for loop
  detection; all session keys expire 24 h after the last write
- approvals: one JSON value per approval plus a sorted-set index; every status change is a WATCH/MULTI
  transaction, so an approved call is consumed exactly once even when two replicas race for it
- MCP pins and pending definitions: one hash per server plus a set of server names

The scan cache stays local to each replica (it is a pure cache of deterministic scan results).
`store.session(id)` returns a proxy whose attribute writes go to Redis: `steps` and `usd` are written as
atomic increments of the difference, so `store.session(id).steps += 1` on two replicas never loses a step.
"""

from __future__ import annotations

import dataclasses
import json
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from typing import Any

from bouncer.store import Approval, Store, day_key

SESSION_TTL_SECONDS = 24 * 3600
USD_TTL_SECONDS = 2 * 24 * 3600
WINDOW_TTL_SECONDS = 2 * 3600
APPROVAL_KEEP_SECONDS = 7 * 24 * 3600  # decided approvals stay listed this long after they expire
MAX_TOOL_CALLS = 200  # same as the in-memory deque


class RedisUnavailable(RuntimeError):
    pass


def _s(v: Any) -> str:
    return v.decode() if isinstance(v, bytes) else str(v)


class SessionProxy:
    """Snapshot of one session read in a single round trip; writes go straight to Redis."""

    _FIELDS = ("steps", "usd", "breaker_until", "breaker_reason", "last_seen")

    def __init__(self, store: RedisStore, session_id: str, raw: dict, taint: set) -> None:
        object.__setattr__(self, "_store", store)
        object.__setattr__(self, "_id", session_id)
        object.__setattr__(self, "_steps", int(float(_s(raw.get(b"steps", b"0")))))
        object.__setattr__(self, "_usd", float(_s(raw.get(b"usd", b"0"))))
        object.__setattr__(self, "_breaker_until", float(_s(raw.get(b"breaker_until", b"0"))))
        object.__setattr__(self, "_breaker_reason", _s(raw.get(b"breaker_reason", b"")))
        object.__setattr__(self, "_last_seen", float(_s(raw.get(b"last_seen", b"0"))))
        object.__setattr__(self, "taint", {_s(t) for t in taint})

    @property
    def steps(self) -> int:
        return self._steps

    @property
    def usd(self) -> float:
        return self._usd

    @property
    def breaker_until(self) -> float:
        return self._breaker_until

    @property
    def breaker_reason(self) -> str:
        return self._breaker_reason

    @property
    def last_seen(self) -> float:
        return self._last_seen

    @property
    def taint_sources(self) -> dict[str, list[str]]:
        return self._store._taint_sources(self._id, self.taint)

    @property
    def tool_calls(self) -> list[tuple[float, str]]:
        return self._store._tool_calls(self._id)

    def __setattr__(self, name: str, value: Any) -> None:
        st, key = self._store, self._store._k("sess", self._id)
        pipe = st.r.pipeline(transaction=False)
        if name == "steps":
            pipe.hincrby(key, "steps", int(value) - self._steps)
        elif name == "usd":
            pipe.hincrbyfloat(key, "usd", float(value) - self._usd)
        elif name in ("breaker_until", "breaker_reason", "last_seen"):
            pipe.hset(key, name, value)
        else:
            raise AttributeError(f"session attribute {name} is read-only")
        pipe.expire(key, SESSION_TTL_SECONDS)
        res = pipe.execute()
        if name == "steps":
            value = int(res[0])
        elif name == "usd":
            value = float(res[0])
        object.__setattr__(self, "_" + name, value)


class _ServerHash(MutableMapping):
    """tool -> definition hash for one MCP server, stored in one Redis hash."""

    def __init__(self, store: RedisStore, kind: str, server: str) -> None:
        self.st, self.kind, self.server = store, kind, server
        self.key = store._k(kind, server)

    def __getitem__(self, tool: str) -> str:
        v = self.st.r.hget(self.key, tool)
        if v is None:
            raise KeyError(tool)
        return _s(v)

    def __setitem__(self, tool: str, value: str) -> None:
        pipe = self.st.r.pipeline(transaction=False)
        pipe.hset(self.key, tool, value)
        pipe.sadd(self.st._k(self.kind + "_servers"), self.server)
        pipe.execute()

    def __delitem__(self, tool: str) -> None:
        if not self.st.r.hdel(self.key, tool):
            raise KeyError(tool)

    def _all(self) -> dict[str, str]:
        return {_s(k): _s(v) for k, v in self.st.r.hgetall(self.key).items()}

    def __iter__(self) -> Iterator[str]:
        return iter(self._all())

    def __len__(self) -> int:
        return int(self.st.r.hlen(self.key))

    def __eq__(self, other: object) -> bool:
        return self._all() == other if isinstance(other, Mapping) else NotImplemented

    def __repr__(self) -> str:
        return f"_ServerHash({self.server!r}, {self._all()!r})"


class _ServerMap(Mapping):
    """server -> _ServerHash; like the defaultdict in the in-memory store, [server] never raises."""

    def __init__(self, store: RedisStore, kind: str) -> None:
        self.st, self.kind = store, kind

    def __getitem__(self, server: str) -> _ServerHash:
        return _ServerHash(self.st, self.kind, server)

    def get(self, server: str, default: Any = None) -> Any:
        h = _ServerHash(self.st, self.kind, server)
        return h._all() if len(h) else default

    def __contains__(self, server: object) -> bool:
        return isinstance(server, str) and bool(len(_ServerHash(self.st, self.kind, server)))

    def __iter__(self) -> Iterator[str]:
        servers = sorted(_s(s) for s in self.st.r.smembers(self.st._k(self.kind + "_servers")))
        return iter([s for s in servers if s in self])

    def __len__(self) -> int:
        return len(list(iter(self)))


class _Approvals(Mapping):
    """Read view: store.approvals[id] -> Approval."""

    def __init__(self, store: RedisStore) -> None:
        self.st = store

    def __getitem__(self, approval_id: str) -> Approval:
        appr = self.st._load_approval(approval_id)
        if appr is None:
            raise KeyError(approval_id)
        return appr

    def __iter__(self) -> Iterator[str]:
        return iter([a.id for a in self.st._all_approvals()])

    def __len__(self) -> int:
        return len(self.st._all_approvals())


class _TeamRequests(Mapping):
    """team -> requests today (shared by all replicas)."""

    def __init__(self, store: RedisStore) -> None:
        self.st = store

    def _all(self) -> dict[str, int]:
        return {_s(k): int(v) for k, v in self.st.r.hgetall(self.st._k("requests", day_key())).items()}

    def __getitem__(self, team: str) -> int:
        v = self.st.r.hget(self.st._k("requests", day_key()), team)
        if v is None:
            raise KeyError(team)
        return int(v)

    def __iter__(self) -> Iterator[str]:
        return iter(self._all())

    def __len__(self) -> int:
        return len(self._all())


class RedisStore(Store):
    shared = True  # counters persist in Redis; replay_spend from the audit log is not needed

    def __init__(self, client: Any, prefix: str = "bouncer:", scan_cache_size: int = 20000) -> None:
        self.r = client
        self.prefix = prefix
        self._lock = threading.RLock()
        self.scan_cache: OrderedDict[tuple, Any] = OrderedDict()
        self.scan_cache_size = scan_cache_size
        self.scan_cache_hits = 0
        self.scan_cache_misses = 0
        self.mcp_pins = _ServerMap(self, "mcp_pins")
        self.mcp_pending = _ServerMap(self, "mcp_pending")
        self.approvals = _Approvals(self)
        self.team_requests = _TeamRequests(self)

    @classmethod
    def from_url(cls, url: str, prefix: str = "bouncer:") -> RedisStore:
        import redis

        client = redis.Redis.from_url(url, socket_connect_timeout=3, socket_timeout=5, health_check_interval=30)
        try:
            client.ping()
        except Exception as exc:
            raise RedisUnavailable(
                f"BOUNCER_STORE={url}: Redis is not reachable ({type(exc).__name__}: {exc}). Start it with "
                "`docker compose --profile redis up -d redis`, fix the URL, or set BOUNCER_STORE=memory for a single node."
            ) from exc
        return cls(client, prefix)

    def _k(self, *parts: str) -> str:
        return self.prefix + ":".join(parts)

    def reset(self) -> None:
        """Delete every key under the prefix (tests and the self-test only) and clear the local cache."""
        keys = list(self.r.scan_iter(match=self.prefix + "*", count=500))
        for i in range(0, len(keys), 500):
            self.r.delete(*keys[i : i + 500])
        with self._lock:
            self.scan_cache.clear()
            self.scan_cache_hits = self.scan_cache_misses = 0

    # ------------------------------------------------------------------ budgets
    def team_spend_today(self, team: str) -> float:
        v = self.r.get(self._k("usd", team, day_key()))
        return float(v) if v is not None else 0.0

    def add_spend(self, team: str, session_id: str, usd: float, tokens: int, gpu_seconds: float) -> None:
        now = time.time()
        nonce = secrets.token_hex(3)
        usd_key, tok_key = self._k("usd", team, day_key(now)), self._k("tokens", team)
        sess_key, req_key = self._k("sess", session_id), self._k("requests", day_key(now))
        pipe = self.r.pipeline(transaction=False)
        pipe.incrbyfloat(usd_key, usd)
        pipe.expire(usd_key, USD_TTL_SECONDS)
        pipe.zadd(tok_key, {f"{now}:{int(tokens)}:{nonce}": now})
        pipe.zremrangebyscore(tok_key, "-inf", now - 60)
        pipe.expire(tok_key, WINDOW_TTL_SECONDS)
        if gpu_seconds:
            gpu_key = self._k("gpu", team)
            pipe.zadd(gpu_key, {f"{now}:{float(gpu_seconds)}:{nonce}": now})
            pipe.zremrangebyscore(gpu_key, "-inf", now - 3600)
            pipe.expire(gpu_key, WINDOW_TTL_SECONDS)
        pipe.hincrbyfloat(sess_key, "usd", usd)
        pipe.expire(sess_key, SESSION_TTL_SECONDS)
        pipe.hincrby(req_key, team, 1)
        pipe.expire(req_key, USD_TTL_SECONDS)
        pipe.execute()

    def replay_spend(self, events: Any) -> int:
        """No-op: the counters already live in Redis and survive a gateway restart."""
        return 0

    def _window(self, key: str, seconds: float) -> float:
        cutoff = time.time() - seconds
        pipe = self.r.pipeline(transaction=False)
        pipe.zremrangebyscore(key, "-inf", f"({cutoff}")
        pipe.zrangebyscore(key, cutoff, "+inf")
        _, members = pipe.execute()
        return float(sum(float(_s(m).split(":")[1]) for m in members))

    def tokens_last_minute(self, team: str) -> int:
        return int(self._window(self._k("tokens", team), 60))

    def gpu_seconds_last_hour(self, team: str) -> float:
        return self._window(self._k("gpu", team), 3600)

    # ------------------------------------------------------------------ sessions
    def session(self, session_id: str) -> SessionProxy:  # type: ignore[override]
        key, tkey = self._k("sess", session_id), self._k("sess", session_id, "taint")
        pipe = self.r.pipeline(transaction=False)
        pipe.hset(key, "last_seen", time.time())
        pipe.expire(key, SESSION_TTL_SECONDS)
        pipe.hgetall(key)
        pipe.smembers(tkey)
        _, _, raw, taint = pipe.execute()
        return SessionProxy(self, session_id, raw, taint)

    _sess = session

    def mark_taint(self, session_id: str, kind: str, source: str) -> None:
        tkey, skey = self._k("sess", session_id, "taint"), self._k("sess", session_id, "src", kind)
        pipe = self.r.pipeline(transaction=False)
        pipe.sadd(tkey, kind)
        pipe.zadd(skey, {source: time.time()}, nx=True)  # first time a source was seen keeps its place
        pipe.expire(tkey, SESSION_TTL_SECONDS)
        pipe.expire(skey, SESSION_TTL_SECONDS)
        pipe.execute()

    def _taint_sources(self, session_id: str, kinds: set[str]) -> dict[str, list[str]]:
        kinds_l = sorted(kinds)
        pipe = self.r.pipeline(transaction=False)
        for kind in kinds_l:
            pipe.zrange(self._k("sess", session_id, "src", kind), 0, -1)
        return {kind: [_s(m) for m in members] for kind, members in zip(kinds_l, pipe.execute(), strict=True)}

    def record_tool_call(self, session_id: str, call_hash: str) -> None:
        now = time.time()
        key = self._k("sess", session_id, "calls")
        pipe = self.r.pipeline(transaction=False)
        pipe.zadd(key, {f"{call_hash}|{now}|{secrets.token_hex(3)}": now})
        pipe.zremrangebyrank(key, 0, -(MAX_TOOL_CALLS + 1))
        pipe.expire(key, SESSION_TTL_SECONDS)
        pipe.execute()

    def _tool_calls(self, session_id: str) -> list[tuple[float, str]]:
        rows = self.r.zrange(self._k("sess", session_id, "calls"), 0, -1, withscores=True)
        return [(float(score), _s(m).split("|", 1)[0]) for m, score in rows]

    def identical_calls(self, session_id: str, call_hash: str, window_seconds: float) -> int:
        cutoff = time.time() - window_seconds
        members = self.r.zrangebyscore(self._k("sess", session_id, "calls"), cutoff, "+inf")
        return sum(1 for m in members if _s(m).split("|", 1)[0] == call_hash)

    # ------------------------------------------------------------------ approvals
    def _akey(self, approval_id: str) -> str:
        return self._k("approval", approval_id)

    def _load_approval(self, approval_id: str) -> Approval | None:
        raw = self.r.get(self._akey(approval_id))
        return Approval(**json.loads(raw)) if raw is not None else None

    def _save_args(self, appr: Approval) -> tuple[str, str, int]:
        ttl = max(60, int(max(appr.expires_at, appr.allow_until or 0) - time.time()) + APPROVAL_KEEP_SECONDS)
        return self._akey(appr.id), json.dumps(dataclasses.asdict(appr)), ttl

    def _all_approvals(self) -> list[Approval]:
        index = self._k("approvals")
        ids = [_s(i) for i in self.r.zrange(index, 0, -1)]
        if not ids:
            return []
        raws = self.r.mget([self._akey(i) for i in ids])
        out, gone = [], []
        for i, raw in zip(ids, raws, strict=True):
            if raw is None:
                gone.append(i)
            else:
                out.append(Approval(**json.loads(raw)))
        if gone:
            self.r.zrem(index, *gone)
        return out

    def _update(self, approval_id: str, fn: Callable[[Approval], bool]) -> tuple[Approval | None, bool]:
        """Read, change and write one approval atomically (optimistic WATCH/MULTI, retried on conflict).

        fn mutates the approval and returns True when it should be written. Returns (approval, written)."""
        import redis

        key = self._akey(approval_id)
        with self.r.pipeline(transaction=True) as pipe:
            for _ in range(50):
                try:
                    pipe.watch(key)
                    raw = pipe.get(key)
                    if raw is None:
                        pipe.reset()
                        return None, False
                    appr = Approval(**json.loads(raw))
                    if not fn(appr):
                        pipe.reset()
                        return appr, False
                    _, value, ttl = self._save_args(appr)
                    pipe.multi()
                    pipe.set(key, value, ex=ttl)
                    pipe.execute()
                    return appr, True
                except redis.WatchError:
                    continue
        raise RuntimeError(f"approval {approval_id}: too many concurrent updates")

    def create_approval(self, **kw: Any) -> Approval:
        now = time.time()
        ttl = kw.pop("ttl_seconds")
        appr = Approval(id="apr_" + secrets.token_hex(4), created_at=now, expires_at=now + ttl, **kw)
        for existing in self._all_approvals():
            if (
                existing.status == "pending"
                and existing.call_hash == appr.call_hash
                and existing.principal == appr.principal
                and existing.expires_at > now
            ):
                return existing
        key, value, ex = self._save_args(appr)
        pipe = self.r.pipeline(transaction=True)
        pipe.set(key, value, ex=ex)
        pipe.zadd(self._k("approvals"), {appr.id: appr.created_at})
        pipe.execute()
        return appr

    def decide_approval(self, approval_id: str, decision: str, note: str | None, ttl_seconds: int) -> Approval | None:
        def change(appr: Approval) -> bool:
            now = time.time()
            if appr.status == "pending" and appr.expires_at < now:
                appr.status = "expired"
                return True
            if appr.status != "pending":
                return False
            appr.status = "approved" if decision == "approve" else "denied"
            appr.decided_at = now
            appr.note = note
            if appr.status == "approved":
                appr.allow_until = now + ttl_seconds
            return True

        appr, _ = self._update(approval_id, change)
        return appr

    def approved(self, principal_key: str, call_hash: str, session_id: str | None = None) -> Approval | None:
        """Consume one matching approval; the approved -> used transition is a transaction, so only one
        replica wins it."""
        now = time.time()

        def match(a: Approval) -> bool:
            return (
                a.status == "approved"
                and (a.principal_key or a.principal) == principal_key
                and a.call_hash == call_hash
                and (session_id is None or a.session_id == session_id)
                and (a.allow_until or 0) >= now
            )

        def consume(a: Approval) -> bool:
            if not match(a):
                return False
            a.status = "used"
            return True

        for cand in sorted(self._all_approvals(), key=lambda a: a.created_at):
            if not match(cand):
                continue
            appr, written = self._update(cand.id, consume)
            if written:
                return appr
        return None

    def list_approvals(self, status: str | None = None) -> list[Approval]:
        now = time.time()
        out = []
        for appr in self._all_approvals():
            if appr.status == "pending" and appr.expires_at < now:

                def expire(a: Approval) -> bool:
                    if a.status == "pending" and a.expires_at < time.time():
                        a.status = "expired"
                        return True
                    return False

                updated, _ = self._update(appr.id, expire)
                if updated is None:
                    continue
                appr = updated
            if status and appr.status != status:
                continue
            out.append(appr)
        return sorted(out, key=lambda a: a.created_at, reverse=True)
