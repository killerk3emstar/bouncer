"""Judge client used inside the gateway.

    client = JudgeClient(url="http://localhost:8701", backend="clef-mlx", timeout_ms=4000,
                         cache_ttl_seconds=900, max_concurrency=1)
    result = await client.decide(state, questions, reason="t1_grey_zone")
    if result.error:            # "timeout" | "unavailable" | "bad_response" | "bad_request" | "backend_error" | "disabled"
        ...apply policy fail_mode...
    p_injection = result.p("injection", "yes")

Guarantees:
- never raises for network, HTTP or backend errors; ``result.error`` is set instead, so the gateway
  applies its ``fail_mode`` (closed = block, open = allow and log);
- hard timeout: ``timeout_ms`` bounds the whole call, including the wait for a concurrency slot;
- at most ``max_concurrency`` calls in flight; identical concurrent requests share one call;
- TTL LRU cache keyed by sha256 of the canonical JSON of (state, questions); errors are not cached;
- ``backend="fake"`` runs the deterministic fake backend in-process (no HTTP, no model), which is
  what ``make test`` uses. Pass ``fake=FakeBackend(...)`` to script answers in tests;
- ``backend="none"`` never calls anything and returns ``invoked=False, error="disabled"``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from typing import Any

import httpx

from judge.backends.base import BackendError, QuestionError, normalize_questions, output_keys


@dataclass(frozen=True)
class JudgeResult:
    invoked: bool
    reason: str
    backend: str
    answers: dict[str, dict[str, float]]
    latency_ms: float
    cached: bool = False
    error: str | None = None
    model: str | None = None
    detail: str | None = None
    input_tokens: int | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def p(self, question: str, option: str) -> float | None:
        """Probability of one option, or None when the question was not answered."""
        return (self.answers.get(question) or {}).get(option)

    def to_audit(self) -> dict[str, Any]:
        """The ``judge`` object of an audit event (PLAN.md section 3)."""
        out = {k: v for k, v in asdict(self).items() if k in
               ("invoked", "reason", "backend", "answers", "latency_ms", "cached", "error", "model")}
        if out["error"] is None:
            out.pop("error")
        return out


def cache_key(state: Any, questions: dict[str, Any]) -> str:
    blob = json.dumps({"state": state, "questions": questions}, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class JudgeClient:
    def __init__(
        self,
        url: str = "http://localhost:8701",
        backend: str = "clef-mlx",
        timeout_ms: float = 4000,
        cache_ttl_seconds: float = 900,
        max_concurrency: int = 1,
        transport: httpx.AsyncBaseTransport | None = None,
        *,
        fake: Any = None,
        cache_max_entries: int = 2048,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = url.rstrip("/")
        self.backend = (backend or "none").lower()
        self.timeout_s = max(0.001, float(timeout_ms) / 1000.0)
        self.cache_ttl = float(cache_ttl_seconds or 0)
        self.cache_max_entries = cache_max_entries
        self.max_concurrency = max(1, int(max_concurrency))
        self._transport = transport
        self._clock = clock
        self._sem = asyncio.Semaphore(self.max_concurrency)
        self._cache: OrderedDict[str, tuple[float, JudgeResult]] = OrderedDict()
        self._inflight: dict[str, asyncio.Future] = {}
        self._http: httpx.AsyncClient | None = None
        self._fake = fake
        if self.backend == "fake" and self._fake is None:
            from judge.backends.fake import FakeBackend

            self._fake = FakeBackend()
        self.stats = {"calls": 0, "cache_hits": 0, "shared": 0, "errors": 0}

    @classmethod
    def from_policy(cls, judge_cfg: dict[str, Any], **kwargs: Any) -> JudgeClient:
        """Build from the ``judge:`` section of policy/bouncer.yaml."""
        return cls(
            url=judge_cfg.get("url", "http://localhost:8701"),
            backend=judge_cfg.get("backend", "clef-mlx"),
            timeout_ms=judge_cfg.get("timeout_ms", 4000),
            cache_ttl_seconds=judge_cfg.get("cache_ttl_seconds", 900),
            max_concurrency=judge_cfg.get("max_concurrency", 1),
            **kwargs,
        )

    @property
    def fake(self) -> Any:
        """The in-process fake backend (backend="fake" only); use ``client.fake.script(...)`` in tests."""
        return self._fake

    # ------------------------------------------------------------------ public API
    async def decide(self, state: Any, questions: dict[str, Any], reason: str) -> JudgeResult:
        t0 = time.perf_counter()
        if self.backend == "none":
            return JudgeResult(False, reason, "none", {}, 0.0, error="disabled", detail="judge.backend is none")
        try:
            qs = normalize_questions(questions)
        except QuestionError as exc:
            return self._fail(reason, t0, "bad_request", str(exc))

        key = cache_key(state, qs)
        hit = self._cache_get(key)
        if hit is not None:
            self.stats["cache_hits"] += 1
            return replace(hit, reason=reason, cached=True, latency_ms=_ms(t0))

        pending = self._inflight.get(key)
        if pending is not None:
            self.stats["shared"] += 1
            try:
                async with asyncio.timeout(self.timeout_s):
                    shared: JudgeResult = await asyncio.shield(pending)
            except TimeoutError:
                return self._fail(reason, t0, "timeout", f"no answer within {self.timeout_s * 1000:.0f} ms")
            return replace(shared, reason=reason, cached=shared.error is None, latency_ms=_ms(t0))

        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._inflight[key] = fut
        result: JudgeResult | None = None
        try:
            result = await self._call(state, qs, reason, t0)
            if result.error is None and self.cache_ttl > 0:
                self._cache_put(key, result)
            return result
        finally:
            self._inflight.pop(key, None)
            if not fut.done():
                fut.set_result(result or JudgeResult(True, reason, self.backend, {}, _ms(t0), error="cancelled"))

    async def health(self) -> dict[str, Any]:
        if self.backend == "none":
            return {"status": "disabled", "backend": "none", "loaded": False}
        if self.backend == "fake":
            return {"status": "ok", "backend": "fake", "model": self._fake.model, "loaded": True, "in_process": True}
        try:
            async with asyncio.timeout(self.timeout_s):
                resp = await self._client().get("/health")
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            return {"status": "unavailable", "backend": self.backend, "loaded": False, "error": f"{type(exc).__name__}: {exc}"}

    def cache_clear(self) -> None:
        self._cache.clear()

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ------------------------------------------------------------------ internals
    async def _call(self, state: Any, qs: dict[str, dict[str, Any]], reason: str, t0: float) -> JudgeResult:
        self.stats["calls"] += 1
        try:
            async with asyncio.timeout(self.timeout_s):
                async with self._sem:
                    if self.backend == "fake":
                        return await self._call_fake(state, qs, reason, t0)
                    return await self._call_http(state, qs, reason, t0)
        except TimeoutError:
            return self._fail(reason, t0, "timeout", f"no answer within {self.timeout_s * 1000:.0f} ms")

    async def _call_fake(self, state: Any, qs: dict[str, dict[str, Any]], reason: str, t0: float) -> JudgeResult:
        try:
            decision = await self._fake.adecide(state, qs)
        except BackendError as exc:
            return self._fail(reason, t0, "backend_error", str(exc))
        return JudgeResult(True, reason, "fake", decision.answers, _ms(t0), model=self._fake.model)

    async def _call_http(self, state: Any, qs: dict[str, dict[str, Any]], reason: str, t0: float) -> JudgeResult:
        try:
            resp = await self._client().post("/v1/decide", json={"state": state, "questions": qs})
        except httpx.TimeoutException:
            return self._fail(reason, t0, "timeout", "HTTP timeout")
        except (httpx.TransportError, OSError) as exc:
            return self._fail(reason, t0, "unavailable", f"{type(exc).__name__}: {exc}")
        if resp.status_code != 200:
            code = {503: "unavailable", 502: "backend_error", 500: "backend_error"}.get(
                resp.status_code, "bad_request" if 400 <= resp.status_code < 500 else "backend_error")
            return self._fail(reason, t0, code, f"HTTP {resp.status_code}: {resp.text[:300]}")
        try:
            body = resp.json()
            answers = _validate_answers(body.get("answers"), qs)
        except (ValueError, TypeError, AttributeError) as exc:
            return self._fail(reason, t0, "bad_response", str(exc)[:300])
        return JudgeResult(True, reason, str(body.get("backend") or self.backend), answers, _ms(t0),
                           model=body.get("model"), input_tokens=body.get("input_tokens"))

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(base_url=self.url, transport=self._transport,
                                           timeout=httpx.Timeout(self.timeout_s + 1.0))
        return self._http

    def _fail(self, reason: str, t0: float, error: str, detail: str) -> JudgeResult:
        self.stats["errors"] += 1
        return JudgeResult(True, reason, self.backend, {}, _ms(t0), error=error, detail=detail)

    def _cache_get(self, key: str) -> JudgeResult | None:
        if self.cache_ttl <= 0:
            return None
        item = self._cache.get(key)
        if item is None:
            return None
        expires, result = item
        if self._clock() >= expires:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return result

    def _cache_put(self, key: str, result: JudgeResult) -> None:
        self._cache[key] = (self._clock() + self.cache_ttl, result)
        self._cache.move_to_end(key)
        while len(self._cache) > self.cache_max_entries:
            self._cache.popitem(last=False)


def _validate_answers(answers: Any, qs: dict[str, dict[str, Any]]) -> dict[str, dict[str, float]]:
    if not isinstance(answers, dict):
        raise ValueError("response has no 'answers' object")
    out: dict[str, dict[str, float]] = {}
    for qid, q in qs.items():
        probs = answers.get(qid)
        if not isinstance(probs, dict):
            raise ValueError(f"answer for question '{qid}' is missing")
        clean = {}
        for k in output_keys(q):
            v = probs.get(k)
            if not isinstance(v, int | float) or isinstance(v, bool) or not 0.0 <= float(v) <= 1.0:
                raise ValueError(f"answer for '{qid}' option '{k}' is not a probability: {v!r}")
            clean[k] = float(v)
        if abs(sum(clean.values()) - 1.0) > 0.01:
            raise ValueError(f"probabilities for '{qid}' sum to {sum(clean.values()):.3f}, not 1")
        out[qid] = clean
    return out


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)
