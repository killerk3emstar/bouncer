"""Process-wide gateway state: policy manager, engine, upstream clients, judge and classifier."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from bouncer.audit import AuditLog
from bouncer.pipeline import Engine
from bouncer.policy.loader import PolicyManager
from bouncer.store import Store
from bouncer.telemetry import Telemetry

log = logging.getLogger("bouncer.gateway")


@dataclass
class Settings:
    policy_path: str = "policy/bouncer.yaml"
    audit_path: str | None = None  # None = policy.audit.path
    t1: str = "auto"  # onnx | fake | off | auto (onnx when the model files exist)
    t1_model_path: str = "models/deberta-pi-v2/onnx"
    judge_override: str | None = None  # force a judge backend (tests: "fake")
    admin_token: str | None = None
    watch: bool = True
    root: str = "."
    key_overrides: dict[str, str] | None = None  # env var name -> key; used instead of os.environ when set

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            policy_path=os.environ.get("BOUNCER_POLICY", "policy/bouncer.yaml"),
            audit_path=os.environ.get("BOUNCER_AUDIT_PATH") or None,
            t1=os.environ.get("BOUNCER_T1", "auto"),
            t1_model_path=os.environ.get("T1_MODEL_PATH", "models/deberta-pi-v2/onnx"),
            judge_override=os.environ.get("BOUNCER_JUDGE") or None,
            admin_token=_admin_token_from_env(),
            watch=os.environ.get("BOUNCER_WATCH", "1") != "0",
        )


def _admin_token_from_env() -> str | None:
    """The admin API (/api, /admin, /reports) always needs a token, unless explicitly turned off.

    Unset: a random token is generated for this process and logged once (make dev prints a dashboard
    link that carries it). "off": no token (only for a gateway that nothing else on the host can reach)."""
    import secrets as _secrets

    value = os.environ.get("BOUNCER_ADMIN_TOKEN", "").strip()
    if value.lower() == "off":
        log.warning("BOUNCER_ADMIN_TOKEN=off: the admin API is open to anyone who can reach this port")
        return None
    if value:
        return value
    token = "adm_" + _secrets.token_urlsafe(18)
    os.environ["BOUNCER_ADMIN_TOKEN"] = token
    log.warning("BOUNCER_ADMIN_TOKEN not set; generated one for this run. Dashboard: http://localhost:%s/ui/?token=%s", os.environ.get("BOUNCER_PORT", "8700"), token)
    return token


class JudgeAdapter:
    """Holds a judge client matching the active policy's judge section (rebuilt when it changes)."""

    def __init__(self, gateway: GatewayState) -> None:
        self.gw = gateway
        self._key: tuple | None = None
        self._client: Any = None
        self.fake_backend: Any = None  # tests can script answers on this

    def _client_for_policy(self) -> Any:
        jc = self.gw.policies.current.doc.judge
        backend = self.gw.settings.judge_override or jc.backend
        key = (backend, jc.url, jc.timeout_ms, jc.cache_ttl_seconds, jc.max_concurrency)
        if key != self._key:
            self._key = key
            self._client = None
            if backend != "none":
                try:
                    from judge.client import JudgeClient

                    kwargs = dict(
                        url=jc.url,
                        backend=backend,
                        timeout_ms=jc.timeout_ms,
                        cache_ttl_seconds=jc.cache_ttl_seconds,
                        max_concurrency=jc.max_concurrency,
                    )
                    if backend == "fake" and self.fake_backend is not None:
                        kwargs["fake"] = self.fake_backend
                    self._client = JudgeClient(**kwargs)
                except Exception:
                    log.exception("judge client unavailable")
                    self._client = None
        return self._client

    @property
    def backend(self) -> str:
        jc = self.gw.policies.current.doc.judge
        return self.gw.settings.judge_override or jc.backend

    async def decide(self, state: dict[str, Any], questions: dict[str, Any], reason: str) -> Any:
        client = self._client_for_policy()
        if client is None:
            return {"invoked": False, "reason": reason, "backend": self.backend, "error": "unavailable", "answers": {}}
        return await client.decide(state, questions, reason)


def build_classifier(settings: Settings) -> Any:
    mode = settings.t1
    model_file = Path(settings.t1_model_path) / "model.onnx"
    if mode == "auto":
        mode = "onnx" if model_file.exists() else "fake"
    if mode == "off":
        return None
    try:
        if mode == "onnx":
            from bouncer.t1.classifier import OnnxInjectionClassifier

            return OnnxInjectionClassifier(settings.t1_model_path)
        from bouncer.t1.fake import FakeInjectionClassifier

        return FakeInjectionClassifier()
    except Exception:
        log.exception("T1 classifier unavailable (%s)", mode)
        return None


def build_lang_detector() -> Any:
    try:
        from bouncer.t1.lang import is_probably_english

        return is_probably_english
    except Exception:
        return None


@dataclass
class GatewayState:
    settings: Settings
    policies: PolicyManager
    store: Store
    audit: AuditLog
    telemetry: Telemetry
    engine: Engine
    judge: JudgeAdapter
    upstream_transport: httpx.AsyncBaseTransport | None = None
    clients: dict[str, httpx.AsyncClient] = field(default_factory=dict)
    feed_store: Any = None
    started_at: float = 0.0
    model_slots: dict[tuple[str, int], Any] = field(default_factory=dict)

    def model_slot(self, model: str, limit: int | None) -> Any:
        """asyncio.Semaphore for models.<id>.max_concurrency (protects a shared local GPU); None = no limit."""
        import asyncio

        if not limit:
            return None
        key = (model, int(limit))
        sem = self.model_slots.get(key)
        if sem is None:
            sem = self.model_slots[key] = asyncio.Semaphore(int(limit))
        return sem

    def client_for(self, base_url: str) -> httpx.AsyncClient:
        c = self.clients.get(base_url)
        if c is None:
            c = httpx.AsyncClient(
                base_url=base_url,
                transport=self.upstream_transport,
                timeout=httpx.Timeout(connect=5.0, read=180.0, write=30.0, pool=10.0),
            )
            self.clients[base_url] = c
        return c

    async def aclose(self) -> None:
        for c in self.clients.values():
            await c.aclose()
        self.clients.clear()
