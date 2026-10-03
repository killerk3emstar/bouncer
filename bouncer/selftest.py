"""YAML test-case runner. Used by `make test` (tests/test_cases.py) and by the dashboard's
"Run self-test" button (POST /api/selftest).

Each case runs through the real gateway app in-process, with the simulated upstream
(demo/mock_upstream.py) mounted as an ASGI transport, the deterministic fake T1 classifier and
the fake T2 judge. No network, no models.

Case format: see tests/cases/README.md.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

from demo.mock_upstream import MockState
from demo.mock_upstream import create_app as create_mock

ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = ROOT / "tests" / "cases"


def deep_merge(base: Any, patch: Any) -> Any:
    """Merge patch into a copy of base. A None value in the patch deletes the key."""
    if isinstance(base, dict) and isinstance(patch, dict):
        out = dict(base)
        for k, v in patch.items():
            if v is None:
                out.pop(k, None)
            elif k in out:
                out[k] = deep_merge(out[k], v)
            else:
                out[k] = copy.deepcopy(v)
        return out
    return copy.deepcopy(patch)


def load_cases(directory: Path | str = CASES_DIR) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sorted(Path(directory).glob("*.yaml")):
        data = yaml.safe_load(path.read_text()) or []
        if isinstance(data, dict):
            data = data.get("cases", [])
        for case in data:
            if not isinstance(case, dict) or "id" not in case:
                continue
            case = dict(case)
            case["_file"] = path.name
            if case["id"] in seen:
                case["_duplicate"] = True
            seen.add(case["id"])
            cases.append(case)
    return cases


@dataclass
class CaseResult:
    id: str
    control: str
    kind: str
    passed: bool
    failures: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    actions: list[str] = field(default_factory=list)
    findings: list[list[str]] = field(default_factory=list)
    trace_ids: list[str] = field(default_factory=list)
    file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "control": self.control,
            "kind": self.kind,
            "passed": self.passed,
            "failures": self.failures,
            "duration_ms": round(self.duration_ms, 2),
            "actions": self.actions,
            "findings": self.findings,
            "trace_ids": self.trace_ids,
            "file": self.file,
        }


def _yaml_keys(obj: Any) -> Any:
    """YAML 1.1 reads the keys yes/no as booleans; map them back to the judge option names."""
    if isinstance(obj, dict):
        return {({True: "yes", False: "no"}.get(k, k) if isinstance(k, bool) else k): _yaml_keys(v) for k, v in obj.items()}
    return obj


def _matches(fid: str, expected: str) -> bool:
    return fid == expected or fid.startswith(expected + ".") or fid.startswith(expected + ":")


def _stream_text(raw: str) -> tuple[str, list[dict[str, Any]]]:
    """Concatenate content and tool-call arguments from an SSE body; also return error objects."""
    text, errors = [], []
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
            errors.append(obj["error"])
            text.append(json.dumps(obj["error"]))
            continue
        for ch in obj.get("choices") or []:
            d = ch.get("delta") or {}
            if d.get("content"):
                text.append(d["content"])
            for tc in d.get("tool_calls") or []:
                fn = tc.get("function") or {}
                text.append(fn.get("name") or "")
                text.append(fn.get("arguments") or "")
    return "".join(text), errors


class CaseRunner:
    """Builds one in-process gateway per distinct policy patch and runs cases against it."""

    def __init__(self, policy_path: str | Path = ROOT / "policy" / "bouncer.yaml", workdir: str | Path | None = None) -> None:
        from bouncer.gateway.app import create_app  # noqa: F401  (import check)

        self.policy_path = Path(policy_path)
        self.base = yaml.safe_load(self.policy_path.read_text())
        self.workdir = Path(workdir or tempfile.mkdtemp(prefix="bouncer-selftest-"))
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.mock_state = MockState()
        self.transport = httpx.ASGITransport(app=create_mock(self.mock_state))
        self.keys: dict[str, str] = {}
        for pid, p in (self.base.get("principals") or {}).items():
            key = f"bk_test_{pid.replace('-', '_')}"
            os.environ[p["key_env"]] = key
            self.keys[pid] = key
        self._apps: dict[str, Any] = {}

    def _app(self, patch: dict[str, Any] | None) -> Any:
        from bouncer.gateway.app import create_app
        from bouncer.gateway.state import Settings

        key = json.dumps(patch or {}, sort_keys=True)
        app = self._apps.get(key)
        if app is not None:
            return app
        doc = deep_merge(self.base, patch or {})
        n = len(self._apps)
        ppath = self.workdir / f"policy-{n}.yaml"
        ppath.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True))
        for pid, p in (doc.get("principals") or {}).items():
            os.environ.setdefault(p["key_env"], f"bk_test_{pid.replace('-', '_')}")
            self.keys.setdefault(pid, os.environ[p["key_env"]])
        try:
            from bouncer.t1.fake import FakeInjectionClassifier

            clf = FakeInjectionClassifier()
        except Exception:
            clf = None
        try:
            from judge.backends.fake import FakeBackend

            fake_judge = FakeBackend()
        except Exception:
            fake_judge = None
        settings = Settings(
            policy_path=str(ppath),
            audit_path=str(self.workdir / f"audit-{n}.jsonl"),
            t1="fake",
            judge_override="fake",
            watch=False,
        )
        app = create_app(settings, upstream_transport=self.transport, classifier=clf, fake_judge=fake_judge)
        app.state.fake_judge = fake_judge
        app.state.fake_t1 = clf
        self._apps[key] = app
        return app

    async def run_case(self, case: dict[str, Any]) -> CaseResult:
        t0 = time.perf_counter()
        res = CaseResult(
            id=str(case.get("id")),
            control=str(case.get("control", "")),
            kind=str(case.get("kind", "")),
            passed=True,
            file=case.get("_file", ""),
        )
        if case.get("_duplicate"):
            res.failures.append(f"duplicate case id {res.id}")
        try:
            app = self._app(case.get("policy_patch"))
        except Exception as exc:
            res.passed = False
            res.failures.append(f"policy_patch failed to load: {exc}")
            return res
        g = app.state.gw
        g.store.reset()
        self.mock_state.reset()
        if app.state.fake_judge is not None:
            app.state.fake_judge.reset()
        if app.state.fake_t1 is not None:
            app.state.fake_t1.overrides = {}
        steps = case.get("steps") or [case]
        session = f"case-{res.id}-{time.time_ns()}"
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://bouncer.test", timeout=30) as client:
            for i, step in enumerate(steps):
                label = f"step {i + 1}: " if len(steps) > 1 else ""
                try:
                    await self._run_step(app, client, case, step, session, res, label)
                except Exception as exc:  # report, do not crash the suite
                    res.failures.append(f"{label}exception {type(exc).__name__}: {exc}")
        res.passed = not res.failures
        res.duration_ms = (time.perf_counter() - t0) * 1000
        return res

    async def _run_step(self, app: Any, client: httpx.AsyncClient, case: dict[str, Any], step: dict[str, Any], session: str, res: CaseResult, label: str) -> None:
        g = app.state.gw
        principal = step.get("principal", case.get("principal", "playground"))
        if step.get("approve_pending"):
            for appr in g.store.list_approvals("pending"):
                g.store.decide_approval(appr.id, "approve", "approved by test", g.policies.current.doc.approvals.ttl_seconds)
        if step.get("t1_scores") and app.state.fake_t1 is not None:
            app.state.fake_t1.overrides.update({k: float(v) for k, v in step["t1_scores"].items()})
        if step.get("judge") and app.state.fake_judge is not None:
            app.state.fake_judge.script(_yaml_keys(step["judge"]))
        if step.get("judge_error") and app.state.fake_judge is not None:
            app.state.fake_judge.error = step["judge_error"]
        mock = step.get("mock_response")
        if mock:
            self.mock_state.script(mock if isinstance(mock, list) else [mock])
        n_before = len(self.mock_state.requests)
        headers = {"X-Bouncer-Session": step.get("session", session)}
        if principal is not None and step.get("auth", True):
            headers["Authorization"] = f"Bearer {step.get('api_key') or self.keys.get(principal, 'bk_unknown')}"
        if "guard" in step:
            resp = await client.post("/v1/guard/check", json=step["guard"], headers=headers)
        else:
            resp = await client.post("/v1/chat/completions", json=copy.deepcopy(step.get("request") or {}), headers=headers)
        raw = resp.text
        text, errors = (_stream_text(raw) if "text/event-stream" in resp.headers.get("content-type", "") else (raw, []))
        trace_id = resp.headers.get("x-bouncer-trace-id")
        if not trace_id:
            try:
                trace_id = (resp.json().get("error") or {}).get("trace_id") or resp.json().get("trace_id")
            except Exception:
                trace_id = None
        event = g.audit.get(trace_id) if trace_id else None
        action = event.get("action") if event else resp.headers.get("x-bouncer-action")
        fids = [f.get("id", "") for f in (event or {}).get("findings", [])]
        res.actions.append(str(action))
        res.findings.append(fids)
        if trace_id:
            res.trace_ids.append(trace_id)
        expect = step.get("expect") or {}
        if "action" in expect and action != expect["action"]:
            res.failures.append(f"{label}expected action {expect['action']}, got {action} (findings: {fids or 'none'}; HTTP {resp.status_code})")
        if "status" in expect and resp.status_code != int(expect["status"]):
            res.failures.append(f"{label}expected HTTP {expect['status']}, got {resp.status_code}")
        for exp in expect.get("findings") or []:
            if not any(_matches(f, exp) for f in fids):
                res.failures.append(f"{label}missing finding {exp} (got: {fids or 'none'})")
        for exp in expect.get("no_findings") or []:
            hit = [f for f in fids if _matches(f, exp)]
            if hit:
                res.failures.append(f"{label}unexpected finding {hit[0]}")
        sent = json.dumps(self.mock_state.requests[n_before:], ensure_ascii=False)
        for s in expect.get("upstream_must_not_contain") or []:
            if s in sent:
                res.failures.append(f"{label}upstream received {s!r}")
        for s in expect.get("upstream_must_contain") or []:
            if s not in sent:
                res.failures.append(f"{label}upstream did not receive {s!r}")
        if expect.get("upstream_called") is not None:
            called = len(self.mock_state.requests) > n_before
            if called != bool(expect["upstream_called"]):
                res.failures.append(f"{label}upstream_called expected {expect['upstream_called']}, got {called}")
        for s in expect.get("response_must_not_contain") or []:
            if s in text:
                res.failures.append(f"{label}response contains {s!r}")
        for s in expect.get("response_must_contain") or []:
            if s not in text:
                res.failures.append(f"{label}response does not contain {s!r}")
        if expect.get("approval") is True and not (event or {}).get("approval_id"):
            res.failures.append(f"{label}expected an approval request")
        if expect.get("downgraded_to") and (event or {}).get("model") != expect["downgraded_to"]:
            res.failures.append(f"{label}expected downgrade to {expect['downgraded_to']}, got model {(event or {}).get('model')}")
        if step.get("sleep_ms"):
            await asyncio.sleep(float(step["sleep_ms"]) / 1000)

    async def run_all(self, cases: list[dict[str, Any]]) -> list[CaseResult]:
        return [await self.run_case(c) for c in cases]


def summarize(results: list[CaseResult]) -> dict[str, Any]:
    by_control: dict[str, dict[str, int]] = {}
    for r in results:
        c = by_control.setdefault(r.control or "unknown", {"total": 0, "passed": 0, "failed": 0, "allow": 0, "block": 0})
        c["total"] += 1
        c["passed" if r.passed else "failed"] += 1
        if r.kind in ("allow", "known_gap", "log"):
            c["allow"] += 1
        else:
            c["block"] += 1
    return {
        "total": len(results),
        "passed": sum(r.passed for r in results),
        "failed": sum(not r.passed for r in results),
        "by_control": by_control,
        "failures": [r.to_dict() for r in results if not r.passed],
    }


def run_selftest(cases_dir: Path | str = CASES_DIR, policy_path: Path | str | None = None) -> dict[str, Any]:
    """Synchronous entry point (runs in a worker thread from the dashboard)."""
    t0 = time.perf_counter()
    runner = CaseRunner(policy_path or ROOT / "policy" / "bouncer.yaml")
    results = asyncio.run(runner.run_all(load_cases(cases_dir)))
    out = summarize(results)
    out["duration_s"] = round(time.perf_counter() - t0, 2)
    out["results"] = [r.to_dict() for r in results]
    return out
