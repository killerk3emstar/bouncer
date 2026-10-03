"""FastAPI application factory for the Bouncer gateway."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import generate_latest

from bouncer.audit import AuditLog
from bouncer.gateway import guard_api, openai_proxy
from bouncer.gateway.state import GatewayState, JudgeAdapter, Settings, build_classifier, build_lang_detector
from bouncer.pipeline import Engine
from bouncer.policy.loader import PolicyManager
from bouncer.store import Store
from bouncer.telemetry import Telemetry

log = logging.getLogger("bouncer")
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


def build_state(
    settings: Settings,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
    classifier: Any = "default",
    fake_judge: Any = None,
) -> GatewayState:
    telemetry = Telemetry()
    shared: dict[str, Any] = {}
    holder: dict[str, Any] = {}

    def on_policy_event(kind: str, data: dict[str, Any]) -> None:
        telemetry.policy_reloads.labels("ok" if kind == "policy.reloaded" else "failed").inc()
        audit = holder.get("audit")
        if audit is not None:
            audit.write({"kind": kind, "trace_id": None, "route": "policy", **data})

    policies = PolicyManager(settings.policy_path, shared=shared, on_event=on_policy_event)
    policy = policies.load_initial()
    audit = AuditLog(settings.audit_path or policy.doc.audit.path, policy.doc.audit.hash_chain)
    holder["audit"] = audit
    store = Store()
    clf = build_classifier(settings) if classifier == "default" else classifier
    gw_state = GatewayState(
        settings=settings,
        policies=policies,
        store=store,
        audit=audit,
        telemetry=telemetry,
        engine=None,  # type: ignore[arg-type]
        judge=None,  # type: ignore[arg-type]
        upstream_transport=upstream_transport,
        started_at=time.time(),
    )
    judge = JudgeAdapter(gw_state)
    judge.fake_backend = fake_judge
    gw_state.judge = judge
    gw_state.engine = Engine(policies, store, audit, telemetry, classifier=clf, judge=judge, lang_detector=build_lang_detector())
    _share_feed_store(gw_state)
    telemetry.policy_info.labels(policy.version).set(policy.loaded_at)
    return gw_state


def _share_feed_store(g: GatewayState) -> None:
    """Keep one signature feed store across policy reloads (so feed state and hit counters survive)."""
    sig = g.policies.current.variant().controls.get("signatures")
    store = getattr(sig, "store", None)
    if store is not None:
        g.policies.shared["feed_store"] = store
        g.feed_store = store


def create_app(
    settings: Settings | None = None,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
    classifier: Any = "default",
    fake_judge: Any = None,
) -> FastAPI:
    load_dotenv(override=False)
    settings = settings or Settings.from_env()
    state = build_state(settings, upstream_transport, classifier, fake_judge)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ANN202
        tasks = []
        if settings.watch:
            tasks.append(asyncio.create_task(_watch_policy(state)))
            tasks.append(asyncio.create_task(_refresh_feed(state)))
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()
            await state.aclose()

    app = FastAPI(title="Bouncer gateway", version="0.1.0", lifespan=lifespan)
    app.state.gw = state
    app.include_router(openai_proxy.router)
    app.include_router(guard_api.router)
    try:
        from bouncer.gateway import admin_api

        app.include_router(admin_api.router)
    except ImportError:
        log.warning("admin API not available")

    @app.middleware("http")
    async def admin_auth(request: Request, call_next):  # noqa: ANN001, ANN202
        token = settings.admin_token
        path = request.url.path
        if token and (path.startswith("/api/") or path.startswith("/admin/") or path.startswith("/reports/")):
            auth = request.headers.get("authorization", "")
            if auth != f"Bearer {token}" and request.query_params.get("token") != token:
                return JSONResponse({"error": {"type": "unauthorized", "message": "Admin token required (Authorization: Bearer <BOUNCER_ADMIN_TOKEN>)."}}, status_code=401)
        return await call_next(request)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        p = state.policies.current
        return {"status": "ok", "policy_version": p.version, "uptime_s": round(time.time() - state.started_at, 1)}

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        return PlainTextResponse(generate_latest(state.telemetry.registry).decode(), media_type="text/plain; version=0.0.4")

    @app.post("/admin/policy/reload")
    async def reload_policy() -> dict[str, Any]:
        changed = state.policies.reload()
        if changed:
            _share_feed_store(state)
        return {"changed": changed, "version": state.policies.current.version, "last_error": state.policies.last_error}

    @app.get("/")
    async def root() -> RedirectResponse:
        return RedirectResponse("/ui/")

    if DASHBOARD_DIR.exists():
        app.mount("/ui", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="ui")
    return app


async def _watch_policy(state: GatewayState) -> None:
    def on_files(changed: set[Path]) -> None:
        if state.feed_store is not None and hasattr(state.feed_store, "maybe_refresh"):
            try:
                state.feed_store.maybe_refresh()
            except Exception:
                log.exception("feed refresh failed")

    state.policies.shared["on_files_changed"] = on_files
    extra = [Path("signatures")]
    while True:
        try:
            await state.policies.watch(extra_paths=extra)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("policy watcher crashed; restarting in 1 s")
            await asyncio.sleep(1)
        _share_feed_store(state)


async def _refresh_feed(state: GatewayState) -> None:
    last_version = state.policies.current.version
    while True:
        await asyncio.sleep(1.0)
        try:
            if state.policies.current.version != last_version:
                last_version = state.policies.current.version
                _share_feed_store(state)
            fs = state.feed_store
            if fs is not None and hasattr(fs, "maybe_refresh"):
                await asyncio.get_running_loop().run_in_executor(None, fs.maybe_refresh)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("feed refresh failed")


def main() -> None:
    import os

    import uvicorn

    logging.basicConfig(level=os.environ.get("BOUNCER_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    port = int(os.environ.get("BOUNCER_PORT", "8700"))
    uvicorn.run(create_app(), host=os.environ.get("BOUNCER_HOST", "127.0.0.1"), port=port, log_level="warning")


if __name__ == "__main__":
    main()
