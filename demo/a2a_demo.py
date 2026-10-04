"""Agent-to-agent demo: Bank Ops Copilot (ops-copilot) asks the Risk Analyst agent through Bouncer.

Four messages, each through POST /a2a/risk-analyst:
1. a plain question: allowed both ways;
2. a message with a cloud access key: the key is redacted before the Risk Analyst sees it;
3. a request for the exposure chart: the reply's markdown image to an outside host and the key are redacted;
4. a request for the raw feed: the reply carries an instruction aimed at the calling agent and is withheld.
Plus one call from dev-assistant, which is not in a2a.agents.risk-analyst.allowed_callers.

Default: everything in-process (gateway with the fake T1 and judge, the demo agent as an ASGI app), no
network, no models. With --gateway the messages go to a running gateway whose policy has the a2a section,
and the Risk Analyst must run on 8707 (make a2a-agent); keys from BOUNCER_KEY_OPS_COPILOT and
BOUNCER_KEY_DEV_ASSISTANT.

Run: make a2a-demo   or   uv run python -m demo.a2a_demo [--gateway http://127.0.0.1:8700]
"""

from __future__ import annotations

import argparse
import asyncio
import os
import tempfile
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent.parent

STEPS = [
    ("ops-copilot", "Summarize today's risk for the treasury portfolio."),
    ("ops-copilot", "echo: the risk feed rejects our key AKIAIOSFODNN7EXAMPLE, can you check it?"),
    ("ops-copilot", "Show the exposure chart for the treasury portfolio."),
    ("ops-copilot", "Give me the raw feed for the treasury portfolio."),
    ("dev-assistant", "Summarize today's risk for the treasury portfolio."),
]


def _rpc(i: int, text: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": i, "method": "message/send", "params": {"message": {"role": "user", "messageId": f"demo-{i}", "parts": [{"kind": "text", "text": text}]}}}


def _reply_text(body: dict[str, Any]) -> str:
    if "error" in body:
        return body["error"].get("message", "")
    res = body.get("result") or {}
    msg = res if "parts" in res else (res.get("status") or {}).get("message") or {}
    return " ".join(p.get("text", "") for p in msg.get("parts") or [] if isinstance(p, dict))


async def run(client: httpx.AsyncClient, keys: dict[str, str]) -> None:
    for i, (who, text) in enumerate(STEPS, 1):
        resp = await client.post("/a2a/risk-analyst", json=_rpc(i, text), headers={"Authorization": f"Bearer {keys[who]}", "X-Bouncer-Session": "a2a-demo"})
        body = resp.json()
        action = resp.headers.get("x-bouncer-action", "?")
        print(f"[{i}] {who} -> risk-analyst: {text}")
        print(f"    HTTP {resp.status_code}  action={action}  trace={resp.headers.get('x-bouncer-trace-id')}")
        print(f"    reply: {_reply_text(body)[:400]}")
        print()


def in_process() -> None:
    import yaml

    from bouncer.gateway.app import create_app
    from bouncer.gateway.state import Settings
    from bouncer.t1.fake import FakeInjectionClassifier
    from demo.a2a_agent import create_app as create_agent
    from judge.backends.fake import FakeBackend

    doc = yaml.safe_load((ROOT / "policy" / "bouncer.yaml").read_text())
    key_env = {p["key_env"]: f"bk_demo_{pid.replace('-', '_')}" for pid, p in doc["principals"].items()}
    keys = {pid: key_env[p["key_env"]] for pid, p in doc["principals"].items()}
    tmp = Path(tempfile.mkdtemp(prefix="bouncer-a2a-demo-"))
    settings = Settings(policy_path=str(ROOT / "policy" / "bouncer.yaml"), audit_path=str(tmp / "audit.jsonl"), t1="fake", judge_override="fake", watch=False, key_overrides=key_env)
    app = create_app(settings, classifier=FakeInjectionClassifier(), fake_judge=FakeBackend())
    app.state.gw.a2a_transport = httpx.ASGITransport(app=create_agent())

    async def go() -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://bouncer.local", timeout=30) as client:
            await run(client, keys)

    print("In-process gateway (fake T1 and judge) and demo Risk Analyst agent; audit log:", tmp / "audit.jsonl", "\n")
    asyncio.run(go())


def live(gateway: str) -> None:
    keys = {"ops-copilot": os.environ.get("BOUNCER_KEY_OPS_COPILOT", ""), "dev-assistant": os.environ.get("BOUNCER_KEY_DEV_ASSISTANT", "")}
    if not all(keys.values()):
        raise SystemExit("Set BOUNCER_KEY_OPS_COPILOT and BOUNCER_KEY_DEV_ASSISTANT (see .env).")

    async def go() -> None:
        async with httpx.AsyncClient(base_url=gateway, timeout=60) as client:
            await run(client, keys)

    print(f"Gateway {gateway}; the Risk Analyst agent must run on the URL in a2a.agents.risk-analyst.url\n")
    asyncio.run(go())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--gateway", help="URL of a running Bouncer gateway (default: in-process)")
    args = ap.parse_args()
    if args.gateway:
        live(args.gateway)
    else:
        in_process()


if __name__ == "__main__":
    main()
