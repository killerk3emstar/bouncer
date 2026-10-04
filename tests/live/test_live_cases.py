"""The YAML cases from tests/cases/, re-run over real HTTP against a running stack.

`make test` runs the same cases in-process with a fake T1 and a scriptable fake judge. Here the
gateway runs its real policy, the real T1 classifier and the real judge, so cases that depend on
test-only hooks are skipped with the reason:
  - policy_patch (the live gateway runs the policy it was started with),
  - judge / judge_error (scripted answers of the fake judge),
  - t1_scores (pinned scores of the fake classifier),
  - a model routed to an upstream that is not the mock (for example qwen3:8b on a real Ollama)
    when the step needs a scripted reply or is expected to reach the model.
Scripted model replies (mock_response) are pushed to MOCK_URL/mock/script; the mock's request log
proves what reached the model (upstream_must_not_contain and friends).
Do not run this while a scripted demo is using the same mock: each step replaces the mock's queue.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from bouncer.selftest import load_cases
from tests.live.helpers import LiveStack, finding_matches, record_latency, wait_s

pytestmark = [pytest.mark.live, pytest.mark.timeout(120)]

CASES = load_cases()
TEST_ONLY_KEYS = ("policy_patch", "judge", "judge_error", "t1_scores")
BLOCKING = ("block", "require_approval")


def unsupported(case: dict[str, Any], live: LiveStack) -> str | None:
    steps = case.get("steps") or [case]
    for key in TEST_ONLY_KEYS:
        if key in case or any(key in s for s in steps):
            return f"uses {key} (a test-only hook of the offline runner; the live stack runs its real policy and models)"
    if any("a2a" in s for s in steps):
        return "A2A case: runs in the offline runner, which mounts the demo A2A agent in-process (live: make a2a-demo GATEWAY=...)"
    for i, step in enumerate(steps):
        principal = step.get("principal", case.get("principal", "playground"))
        if principal is not None and step.get("auth", True) and not step.get("api_key") and principal not in live.keys:
            key_env = ((live.policy_doc.get("principals") or {}).get(principal) or {}).get("key_env", "?")
            return f"no API key for principal {principal} (set {key_env} in the environment or .env)"
        expect = step.get("expect") or {}
        needs_mock = bool(step.get("mock_response")) or any(
            k in expect for k in ("upstream_must_not_contain", "upstream_must_contain", "upstream_called")
        )
        if needs_mock and not live.mock_ok:
            return f"step {i + 1} needs the simulated upstream, which is not reachable at {live.mock_url} (set MOCK_URL)"
        req = step.get("request")
        if req is not None:
            upstream = live.upstream_of(req.get("model"))
            if upstream and upstream not in live.mocked_upstreams:
                if step.get("mock_response") or expect.get("action") not in BLOCKING or expect.get("upstream_called"):
                    return (f"step {i + 1}: model {req.get('model')} routes to upstream '{upstream}' ({live.upstream_url(upstream)}), "
                            "which is not the mock; the case needs a scripted or predictable reply")
    return None


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case_live(case: dict[str, Any], live: LiveStack, record_property) -> None:  # noqa: ANN001
    record_property("control", case.get("control", ""))
    record_property("kind", case.get("kind", ""))
    reason = unsupported(case, live)
    if reason:
        pytest.skip(reason)
    if case.get("kind") == "known_gap":
        # documented gaps of the deterministic layer; with the real T1/T2 they may or may not be stopped,
        # so live runs report them instead of asserting an outcome
        res = live.send(principal=case.get("principal", "playground"), session=live.session(str(case["id"])),
                        request=copy.deepcopy(case.get("request")), guard=None, api_key=None, auth=True,
                        mock_response=case.get("mock_response"))
        record_property("known_gap_action_live", res.action)
        pytest.skip(f"known T0 gap; live stack decided {res.action} (findings: {res.finding_ids or 'none'})")
    session = live.session(str(case["id"]))
    steps = case.get("steps") or [case]
    failures: list[str] = []
    for i, step in enumerate(steps):
        label = f"step {i + 1}: " if len(steps) > 1 else ""
        principal = step.get("principal", case.get("principal", "playground"))
        sid = f"{step['session']}-{live.run_id}" if step.get("session") else session
        if step.get("approve_pending"):
            live.approve_pending(sid)
        expect = step.get("expect") or {}
        res = live.send(
            principal=principal,
            session=sid,
            request=copy.deepcopy(step.get("request")) if "guard" not in step else None,
            guard=step.get("guard"),
            api_key=step.get("api_key"),
            auth=step.get("auth", True),
            mock_response=step.get("mock_response"),
            extra_headers=step.get("headers"),
        )
        record_latency(f"{case['id']}{' ' + label.strip(': ') if label else ''}", res)
        fids = res.finding_ids
        if "action" in expect and res.action != expect["action"]:
            failures.append(f"{label}expected action {expect['action']}, got {res.action} (findings: {fids or 'none'}; HTTP {res.status})")
        if "status" in expect and res.status != int(expect["status"]):
            failures.append(f"{label}expected HTTP {expect['status']}, got {res.status}")
        for exp in expect.get("findings") or []:
            if not any(finding_matches(f, exp) for f in fids):
                failures.append(f"{label}missing finding {exp} (got: {fids or 'none'})")
        for exp in expect.get("no_findings") or []:
            hit = [f for f in fids if finding_matches(f, exp)]
            if hit:
                failures.append(f"{label}unexpected finding {hit[0]}")
        if res.upstream_requests is not None:
            sent = json.dumps(res.upstream_requests, ensure_ascii=False)
            for s in expect.get("upstream_must_not_contain") or []:
                if s in sent:
                    failures.append(f"{label}upstream received {s!r}")
            for s in expect.get("upstream_must_contain") or []:
                if s not in sent:
                    failures.append(f"{label}upstream did not receive {s!r}")
            if expect.get("upstream_called") is not None and bool(res.upstream_requests) != bool(expect["upstream_called"]):
                failures.append(f"{label}upstream_called expected {expect['upstream_called']}, got {bool(res.upstream_requests)}")
        for s in expect.get("response_must_not_contain") or []:
            if s in res.text:
                failures.append(f"{label}response contains {s!r}")
        for s in expect.get("response_must_contain") or []:
            if s not in res.text:
                failures.append(f"{label}response does not contain {s!r}")
        if expect.get("approval") is True and not (res.event or {}).get("approval_id"):
            failures.append(f"{label}expected an approval request")
        if expect.get("downgraded_to") and (res.event or {}).get("model") != expect["downgraded_to"]:
            failures.append(f"{label}expected downgrade to {expect['downgraded_to']}, got model {(res.event or {}).get('model')}")
        wait_s(step.get("sleep_ms"))
    assert not failures, f"[{case.get('_file')}] trace ids in the dashboard: /ui/ (Events)\n" + "\n".join(failures)
