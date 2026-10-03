"""Client for the live test suite: talks to a running Bouncer stack over real HTTP.

Environment:
  BOUNCER_URL           gateway base URL (default http://localhost:8700)
  MOCK_URL              simulated upstream base URL (default http://localhost:8702)
  BOUNCER_ADMIN_TOKEN   admin token, when the gateway requires one for /api/*
  BOUNCER_KEY_*         agent keys, from the environment or ./.env (same names as in the policy)
  LIVE_MOCKED_UPSTREAMS comma-separated upstream names that point at the mock; default: detected
                        from the policy (upstream URL on the mock's port, or host "mock")
  LIVE_TIMEOUT_S        per-request timeout (default 30)
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[2]
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

# Latency rows collected by the tests and printed at the end of the session (conftest.py).
LATENCY_ROWS: list[dict[str, Any]] = []


def env(name: str, default: str) -> str:
    return (os.environ.get(name) or default).rstrip("/")


@dataclass
class StepResult:
    status: int
    action: str | None
    trace_id: str | None
    event: dict[str, Any] | None
    text: str
    upstream_requests: list[dict[str, Any]] | None  # None = mock not observable

    @property
    def finding_ids(self) -> list[str]:
        return [f.get("id", "") for f in (self.event or {}).get("findings", [])]

    @property
    def latency(self) -> dict[str, Any]:
        return (self.event or {}).get("latency_ms") or {}


@dataclass
class LiveStack:
    url: str
    mock_url: str
    timeout: float
    admin_token: str | None
    policy_summary: dict[str, Any]
    policy_doc: dict[str, Any]
    keys: dict[str, str]
    mock_ok: bool
    mocked_upstreams: set[str]
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])

    # ------------------------------------------------------------------ construction

    @classmethod
    def connect(cls) -> LiveStack:
        """Raises RuntimeError with a readable reason when the stack is not reachable."""
        try:
            from dotenv import load_dotenv

            load_dotenv(ROOT / ".env", override=False)
        except Exception:
            pass
        url = env("BOUNCER_URL", "http://localhost:8700")
        if url.endswith("/v1"):
            url = url[:-3]
        mock_url = env("MOCK_URL", "http://localhost:8702")
        timeout = float(os.environ.get("LIVE_TIMEOUT_S", "30"))
        token = os.environ.get("BOUNCER_ADMIN_TOKEN") or None
        try:
            r = httpx.get(url + "/healthz", timeout=3)
            r.raise_for_status()
        except Exception as exc:
            raise RuntimeError(
                f"Bouncer is not reachable at {url}/healthz ({type(exc).__name__}: {exc}). "
                "Start the stack (`make dev`, or `docker compose up -d`) or set BOUNCER_URL."
            ) from exc
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        summary: dict[str, Any] = {}
        doc: dict[str, Any] = {}
        try:
            r = httpx.get(url + "/api/policy", headers=headers, timeout=5)
            if r.status_code == 200:
                summary = r.json()
                doc = yaml.safe_load(summary.get("source") or "") or {}
        except Exception:
            summary, doc = {}, {}
        if not doc:  # admin API locked or unavailable: fall back to the policy file in this checkout
            doc = yaml.safe_load((ROOT / "policy" / "bouncer.yaml").read_text()) or {}
        keys = {}
        for pid, p in (doc.get("principals") or {}).items():
            key = os.environ.get(str(p.get("key_env", "")))
            if key:
                keys[pid] = key
        mock_ok = False
        try:
            mock_ok = httpx.get(mock_url + "/mock/requests", params={"limit": 1}, timeout=3).status_code == 200
        except Exception:
            mock_ok = False
        mocked = cls._detect_mocked(doc, mock_url)
        return cls(url, mock_url, timeout, token, summary, doc, keys, mock_ok, mocked)

    @staticmethod
    def _detect_mocked(doc: dict[str, Any], mock_url: str) -> set[str]:
        override = os.environ.get("LIVE_MOCKED_UPSTREAMS")
        if override is not None:
            return {s.strip() for s in override.split(",") if s.strip()}
        mport = urlsplit(mock_url).port
        out = set()
        for name, up in (doc.get("upstreams") or {}).items():
            u = urlsplit(str((up or {}).get("base_url", "")))
            if u.hostname == "mock" or (u.hostname in LOCAL_HOSTS and u.port == mport):
                out.add(name)
        return out

    # ------------------------------------------------------------------ helpers

    @property
    def admin_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.admin_token}"} if self.admin_token else {}

    @property
    def judge_info(self) -> dict[str, Any]:
        return self.policy_summary.get("judge") or {}

    def upstream_of(self, model: str | None) -> str | None:
        m = (self.policy_doc.get("models") or {}).get(model or "")
        return (m or {}).get("upstream")

    def upstream_url(self, name: str | None) -> str:
        return str(((self.policy_doc.get("upstreams") or {}).get(name or "") or {}).get("base_url", "?"))

    def session(self, label: str) -> str:
        return f"live-{label}-{self.run_id}-{uuid.uuid4().hex[:6]}"

    def mock_script(self, responses: list[dict[str, Any]]) -> None:
        """Replace the mock's reply queue (an empty list clears leftovers from blocked steps)."""
        r = httpx.post(self.mock_url + "/mock/script", json={"responses": responses, "replace": True}, timeout=5)
        r.raise_for_status()

    def mock_count(self) -> int:
        return int(httpx.get(self.mock_url + "/mock/requests", params={"limit": 1}, timeout=5).json().get("count", 0))

    def mock_requests_since(self, n_before: int) -> list[dict[str, Any]]:
        n_now = self.mock_count()
        if n_now <= n_before:
            return []
        r = httpx.get(self.mock_url + "/mock/requests", params={"limit": n_now - n_before}, timeout=5)
        return r.json().get("requests", [])

    def event(self, trace_id: str | None) -> dict[str, Any] | None:
        if not trace_id:
            return None
        try:
            r = httpx.get(f"{self.url}/api/events/{trace_id}", headers=self.admin_headers, timeout=5)
            if r.status_code == 200:
                evs = r.json().get("events") or []
                return evs[0] if evs else None
        except Exception:
            return None
        return None

    def approve_pending(self, session_id: str) -> int:
        r = httpx.get(self.url + "/api/approvals", params={"status": "pending"}, headers=self.admin_headers, timeout=5)
        r.raise_for_status()
        n = 0
        for appr in r.json().get("approvals", []):
            if appr.get("session_id") == session_id:
                httpx.post(f"{self.url}/api/approvals/{appr['id']}", json={"decision": "approve", "note": "approved by live test"},
                           headers=self.admin_headers, timeout=5).raise_for_status()
                n += 1
        return n

    def send(
        self,
        *,
        principal: str | None,
        session: str,
        request: dict[str, Any] | None = None,
        guard: dict[str, Any] | None = None,
        api_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
        auth: bool = True,
        mock_response: Any = None,
        clear_mock: bool = True,
    ) -> StepResult:
        """One request. A scripted reply replaces the mock's queue; otherwise the queue is cleared
        (clear_mock=True, so a reply left over by a blocked step cannot leak into this one) or left alone."""
        headers = {"X-Bouncer-Session": session, **{str(k): str(v) for k, v in (extra_headers or {}).items()}}
        if principal is not None and auth:
            headers["Authorization"] = f"Bearer {api_key or self.keys.get(principal, 'bk_unknown')}"
        n_before = None
        if self.mock_ok:
            if mock_response:
                self.mock_script(mock_response if isinstance(mock_response, list) else [mock_response])
            elif clear_mock:
                self.mock_script([])
            n_before = self.mock_count()
        if guard is not None:
            resp = httpx.post(self.url + "/v1/guard/check", json=guard, headers=headers, timeout=self.timeout)
        else:
            resp = httpx.post(self.url + "/v1/chat/completions", json=request or {}, headers=headers, timeout=self.timeout)
        raw = resp.text
        text = sse_text(raw) if "text/event-stream" in resp.headers.get("content-type", "") else raw
        trace_id = resp.headers.get("x-bouncer-trace-id")
        if not trace_id:
            try:
                body = resp.json()
                trace_id = (body.get("error") or {}).get("trace_id") or body.get("trace_id")
            except Exception:
                trace_id = None
        event = self.event(trace_id)
        action = (event or {}).get("action") or resp.headers.get("x-bouncer-action")
        if action is None and guard is not None:
            try:
                action = resp.json().get("action")
            except Exception:
                pass
        upstream = self.mock_requests_since(n_before) if n_before is not None else None
        return StepResult(resp.status_code, action, trace_id, event, text, upstream)


def sse_text(raw: str) -> str:
    """Concatenate content, tool-call names/arguments and error objects from an SSE body."""
    out = []
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            continue
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            continue
        if "error" in obj:
            out.append(json.dumps(obj["error"]))
            continue
        for ch in obj.get("choices") or []:
            d = ch.get("delta") or {}
            if d.get("content"):
                out.append(d["content"])
            for tc in d.get("tool_calls") or []:
                fn = tc.get("function") or {}
                out.append(fn.get("name") or "")
                out.append(fn.get("arguments") or "")
    return "".join(out)


def finding_matches(fid: str, expected: str) -> bool:
    return fid == expected or fid.startswith(expected + ".") or fid.startswith(expected + ":")


def record_latency(test: str, res: StepResult) -> None:
    lat = res.latency
    judge = (res.event or {}).get("judge") or {}
    t1 = (res.event or {}).get("t1") or []
    LATENCY_ROWS.append(
        {
            "test": test,
            "action": res.action,
            "t0": lat.get("t0"),
            "t1": lat.get("t1"),
            "t2": lat.get("t2"),
            "upstream": lat.get("upstream"),
            "overhead": lat.get("gateway_overhead"),
            "t1_max_score": max((x.get("score") or 0.0 for x in t1), default=None),
            "judge": f"{judge.get('backend')}:{judge.get('reason')}" + (f" error={judge.get('error')}" if judge.get("error") else "")
            if judge.get("invoked") else "-",
            "findings": ",".join(f"{f.get('id')}[{f.get('tier')}]" for f in (res.event or {}).get("findings", [])) or "-",
        }
    )


def wait_s(ms: float | int | None) -> None:
    if ms:
        time.sleep(float(ms) / 1000)
