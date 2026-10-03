"""Gateway layers for eval/run_eval.py: T0 only, and the full pipeline (T0 + T1 + T2).

Each text is checked as a user message through the real gateway code (POST /v1/guard/check
in-process). A text counts as flagged when the decision is block or require_approval.

    uv run python eval/run_eval.py --layers eval.layers:t0,eval.layers:pipeline --datasets bank_ops

`pipeline` uses the real T1 model (models/deberta-pi-v2/onnx) and the judge configured in the policy
(Clef on :8701). If the judge is not reachable the layer reports it and uses fail_mode, so start
`make judge` first.
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FLAG_ACTIONS = {"block", "require_approval"}
# controls that decide whether a text is an attack (secrets/PII redaction is not an injection verdict)
ATTACK_CONTROLS = {"prompt_injection", "signatures", "obfuscation", "supply_chain"}


def _kinds() -> dict[str, str]:
    """text -> dataset kind, so the pipeline layer can route indirect injections as tool results."""
    import json

    out: dict[str, str] = {}
    for path in (ROOT / "eval" / "datasets").glob("*.jsonl"):
        for line in path.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                out[row["text"]] = row.get("kind", "")
    return out


class GatewayLayer:
    def __init__(self, name: str, t1: str, judge: str | None, source: str = "user") -> None:
        from bouncer.gateway.app import build_state
        from bouncer.gateway.state import Settings

        self.name = name
        self.source = source
        tmp = tempfile.mkdtemp(prefix=f"eval-{name}-")
        settings = Settings(
            policy_path=str(ROOT / "policy" / "bouncer.yaml"),
            audit_path=str(Path(tmp) / "audit.jsonl"),
            t1=t1,
            judge_override=judge,
            watch=False,
            key_overrides={},
        )
        self.g = build_state(settings)
        self.principal = self.g.policies.current.principal("playground")
        self.loop = asyncio.new_event_loop()
        self.errors = 0
        self.kinds = _kinds() if source == "auto" else {}

    def _flagged(self, body: dict[str, Any]) -> tuple[bool, float]:
        hits = [
            f
            for f in body["findings"]
            if f["control"] in ATTACK_CONTROLS and f["effective_action"] in FLAG_ACTIONS
        ]
        if body["action"] in FLAG_ACTIONS and hits:
            return True, max(float(f.get("score") or 1.0) for f in hits)
        return False, 0.0

    def predict(self, texts: list[str]) -> list[tuple[bool, float, float]]:
        from bouncer.gateway.guard_api import GuardRequest, run_guard

        out = []
        for i, text in enumerate(texts):
            self.g.store.reset()
            source = self.source
            if source == "auto":  # indirect injections arrive as tool results, everything else as a user message
                source = "tool_result:web.fetch" if self.kinds.get(text) == "indirect" else "user"
            req = GuardRequest(text=text, direction="input" if source == "user" else "tool_result", source=source, session_id=f"eval-{i}")
            t = time.perf_counter()
            res = self.loop.run_until_complete(run_guard(self.g, self.principal, req, route="guard.check"))
            ms = (time.perf_counter() - t) * 1000
            body = res["body"]
            if any(f["rule"] == "judge_unavailable" for f in body["findings"]):
                self.errors += 1
            flagged, score = self._flagged(body)
            out.append((flagged, score, ms))
        return out


def t0() -> GatewayLayer:
    """Deterministic controls only: normalization, heuristics, signatures (no T1, no T2)."""
    return GatewayLayer("t0", t1="off", judge="none", source="auto")


def _require_judge() -> None:
    import urllib.request

    import yaml

    url = yaml.safe_load((ROOT / "policy" / "bouncer.yaml").read_text())["judge"]["url"].rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(url, timeout=2) as r:  # noqa: S310 (local judge)
            if r.status == 200:
                return
    except OSError:
        pass
    raise SystemExit(f"The pipeline layer needs the T2 judge at {url}. Start it with `make judge` (or run `make eval` for T0 and T1 only).")


def pipeline() -> GatewayLayer:
    """T0 + T1 (ONNX) + T2 judge from the policy (Clef on :8701). Indirect-injection texts are sent as
    web.fetch results, everything else as a user message, which is how they reach the gateway in practice."""
    _require_judge()
    return GatewayLayer("pipeline", t1="onnx", judge=None, source="auto")


def pipeline_tool_result() -> GatewayLayer:
    """Same as pipeline, but every text is treated as the result of web.fetch (indirect injection path)."""
    _require_judge()
    return GatewayLayer("pipeline_tool_result", t1="onnx", judge=None, source="tool_result:web.fetch")
