"""Red-team harness: run probes through the real gateway code path in-process.

Mode (a): fake T1 classifier + fake judge (bouncer.t1.fake / judge.backends.fake), the same as
`make test`. Deterministic, no network, no models.

Each probe is a dict with one of:
  text + direction + source      -> POST /v1/guard/check
  request + mock_response        -> POST /v1/chat/completions (model output / tool-call attacks)
  guard                          -> raw /v1/guard/check body (e.g. a tool_call)

Reports action and the finding ids for every probe. Import from pytest or run standalone.
"""

from __future__ import annotations

import asyncio
import copy
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from demo.mock_upstream import MockState  # noqa: E402
from demo.mock_upstream import create_app as create_mock


class Harness:
    def __init__(self, t1: str = "fake") -> None:
        from bouncer.gateway.app import create_app
        from bouncer.gateway.state import Settings

        self.base = yaml.safe_load((ROOT / "policy" / "bouncer.yaml").read_text())
        self.workdir = Path(tempfile.mkdtemp(prefix="redteam-"))
        self.mock_state = MockState()
        self.transport = httpx.ASGITransport(app=create_mock(self.mock_state))
        self.keys: dict[str, str] = {}
        for pid, p in (self.base.get("principals") or {}).items():
            key = f"bk_test_{pid.replace('-', '_')}"
            os.environ[p["key_env"]] = key
            self.keys[pid] = key
        ppath = self.workdir / "policy.yaml"
        ppath.write_text(yaml.safe_dump(self.base, sort_keys=False, allow_unicode=True))

        if t1 == "fake":
            from bouncer.t1.fake import FakeInjectionClassifier

            clf: Any = FakeInjectionClassifier()
        else:
            clf = "default"  # let create_app build the real classifier from settings.t1
        from judge.backends.fake import FakeBackend

        fake_judge = FakeBackend()
        settings = Settings(
            policy_path=str(ppath),
            audit_path=str(self.workdir / "audit.jsonl"),
            t1=t1,
            judge_override="fake",
            watch=False,
        )
        self.app = create_app(settings, upstream_transport=self.transport, classifier=clf, fake_judge=fake_judge)
        self.app.state.fake_judge = fake_judge
        self.app.state.fake_t1 = clf if clf != "default" else None
        self.gw = self.app.state.gw

    async def run(self, probe: dict[str, Any]) -> dict[str, Any]:
        self.gw.store.reset()
        self.mock_state.reset()
        if self.app.state.fake_judge is not None:
            self.app.state.fake_judge.reset()
            if probe.get("judge"):
                self.app.state.fake_judge.script(_yaml_keys(probe["judge"]))
        if self.app.state.fake_t1 is not None and probe.get("t1_scores"):
            self.app.state.fake_t1.overrides.update({k: float(v) for k, v in probe["t1_scores"].items()})
        principal = probe.get("principal", "ops-copilot")
        session = probe.get("session", f"rt-{id(probe)}")
        headers = {"X-Bouncer-Session": session, "Authorization": f"Bearer {self.keys.get(principal, 'bk_x')}"}
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://rt.test", timeout=30) as client:
            if "guard" in probe:
                resp = await client.post("/v1/guard/check", json=probe["guard"], headers=headers)
            elif "check" in probe:
                body = {
                    "text": probe["check"],
                    "direction": probe.get("direction", "input"),
                    "source": probe.get("source", "user"),
                }
                if probe.get("user_request"):
                    body["user_request"] = probe["user_request"]
                resp = await client.post("/v1/guard/check", json=body, headers=headers)
            elif "request" in probe:
                if probe.get("mock_response"):
                    mr = probe["mock_response"]
                    self.mock_state.script(mr if isinstance(mr, list) else [mr])
                resp = await client.post("/v1/chat/completions", json=copy.deepcopy(probe["request"]), headers=headers)
            else:
                raise ValueError(f"probe {probe.get('id')} has no check/guard/request")
        raw = resp.text
        action = resp.headers.get("x-bouncer-action")
        trace_id = resp.headers.get("x-bouncer-trace-id")
        findings: list[str] = []
        try:
            body_json = resp.json()
        except Exception:
            body_json = None
        if trace_id is None and isinstance(body_json, dict):
            trace_id = (body_json.get("error") or {}).get("trace_id") or body_json.get("trace_id")
        event = self.gw.audit.get(trace_id) if trace_id else None
        if event:
            action = event.get("action", action)
            findings = [f.get("id", "") for f in event.get("findings", [])]
        elif isinstance(body_json, dict) and "findings" in body_json:
            findings = [f.get("id", "") for f in body_json["findings"]]
            action = body_json.get("action", action)
        return {
            "id": probe.get("id"),
            "action": action,
            "findings": findings,
            "status": resp.status_code,
            "redacted": (body_json or {}).get("redacted_text") if isinstance(body_json, dict) else None,
            "raw": raw,
        }


def _yaml_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {({True: "yes", False: "no"}.get(k, k) if isinstance(k, bool) else k): _yaml_keys(v) for k, v in obj.items()}
    return obj


async def run_all(probes: list[dict[str, Any]], t1: str = "fake") -> list[dict[str, Any]]:
    h = Harness(t1=t1)
    out = []
    for p in probes:
        try:
            out.append(await h.run(p))
        except Exception as exc:  # noqa: BLE001
            out.append({"id": p.get("id"), "action": f"ERROR {type(exc).__name__}: {exc}", "findings": [], "status": 0})
    return out


def main() -> None:
    probes_path = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "scripts" / "redteam" / "probes.yaml")
    t1 = sys.argv[2] if len(sys.argv) > 2 else "fake"
    probes = yaml.safe_load(Path(probes_path).read_text())
    results = asyncio.run(run_all(probes, t1=t1))
    blocked_actions = {"block", "redact", "require_approval"}
    for r in results:
        p = next((x for x in probes if x.get("id") == r["id"]), {})
        kind = p.get("expect", "block")
        stopped = r["action"] in blocked_actions
        if kind == "block":
            ok = stopped
        else:  # allow
            ok = not stopped
        mark = "ok " if ok else "XX "
        print(f"{mark}{r['id']:<42} action={r['action']:<16} http={r['status']:<4} findings={','.join(r['findings']) or '-'}")
    n = len(results)
    print(f"\n{sum(1 for r in results if r['action'] not in ('block','redact','require_approval'))} allowed / {n} total")


if __name__ == "__main__":
    main()
