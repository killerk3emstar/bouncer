"""In-process harness for the security review checks (fake T1, fake judge, simulated upstream).

Only synthetic test values are used (the AWS documentation example key, the 4111... test card,
example.* domains). Nothing listens on a port.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
os.chdir(ROOT)
os.environ["BOUNCER_WATCH"] = "0"

from bouncer.gateway.app import create_app  # noqa: E402
from bouncer.gateway.state import Settings  # noqa: E402
from demo.mock_upstream import MockState  # noqa: E402
from demo.mock_upstream import create_app as create_mock  # noqa: E402
from judge.backends.fake import FakeBackend  # noqa: E402

KEYS = {
    "BOUNCER_KEY_OPS_COPILOT": "bk_rev_ops",
    "BOUNCER_KEY_DEV_ASSISTANT": "bk_rev_dev",
    "BOUNCER_KEY_INTERN_BOT": "bk_rev_intern",
    "BOUNCER_KEY_PLAYGROUND": "bk_rev_pg",
}
OPS, DEV, INTERN = KEYS["BOUNCER_KEY_OPS_COPILOT"], KEYS["BOUNCER_KEY_DEV_ASSISTANT"], KEYS["BOUNCER_KEY_INTERN_BOT"]
AWS = "AKIAIOSFODNN7EXAMPLE"
CARD = "4111111111111111"


class Stack:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None, admin_token: str | None = None, policy_patch=None) -> None:  # noqa: ANN001
        os.environ.update(KEYS)
        self.tmp = Path(tempfile.mkdtemp(prefix="secrev_"))
        self.policy = self.tmp / "bouncer.yaml"
        shutil.copy(ROOT / "policy" / "bouncer.yaml", self.policy)
        if policy_patch:
            self.policy.write_text(policy_patch(self.policy.read_text()))
        self.audit = self.tmp / "audit.jsonl"
        self.mock = MockState()
        self.judge = FakeBackend().script(
            {"goal_alignment": {"aligned": 0.9, "unclear": 0.05, "misaligned": 0.05}, "exfiltration": {"yes": 0.05, "no": 0.95}}
        )
        self.app = create_app(
            Settings(policy_path=str(self.policy), audit_path=str(self.audit), t1="fake", judge_override="fake", watch=False, admin_token=admin_token),
            upstream_transport=transport or httpx.ASGITransport(app=create_mock(self.mock)),
            fake_judge=self.judge,
        )
        self.gw = self.app.state.gw

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://127.0.0.1")

    async def chat(self, body: dict[str, Any], key: str = OPS, session: str | None = "rev") -> httpx.Response:
        h = {"Authorization": f"Bearer {key}"}
        if session:
            h["X-Bouncer-Session"] = session
        async with self.client() as c:
            return await c.post("/v1/chat/completions", json=body, headers=h)

    async def guard(self, payload: dict[str, Any], key: str = OPS) -> httpx.Response:
        async with self.client() as c:
            return await c.post("/v1/guard/check", json=payload, headers={"Authorization": f"Bearer {key}"})

    def audit_events(self) -> list[dict[str, Any]]:
        return [json.loads(x) for x in self.audit.read_text().splitlines() if x.strip()] if self.audit.exists() else []

    def audit_text(self) -> str:
        return self.audit.read_text() if self.audit.exists() else ""

    def cleanup(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


def json_transport(reply: dict[str, Any], seen: list[dict[str, Any]]) -> httpx.MockTransport:
    """Upstream that returns a fixed chat.completion object and records request bodies."""

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content or b"{}"))
        return httpx.Response(200, json=reply)

    return httpx.MockTransport(handler)
