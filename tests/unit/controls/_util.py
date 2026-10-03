"""Helpers shared by the control unit tests."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from bouncer.controls.injection_heuristics import InjectionHeuristicsControl
from bouncer.controls.normalize import prepare
from bouncer.controls.output_safety import OutputSafetyControl
from bouncer.controls.pii import PiiControl
from bouncer.controls.secrets import SecretsControl
from bouncer.core import Finding, Principal, ScanContext, Segment
from bouncer.policy.schema import ObfuscationCfg, PolicyDoc

ROOT = Path(__file__).resolve().parents[3]
DIRECTION = {"user": "input", "system": "input", "assistant": "output", "tool_result": "tool_result",
             "tool_definition": "tool_definition", "tool_call": "tool_call"}


@lru_cache(maxsize=1)
def policy_doc() -> PolicyDoc:
    with open(ROOT / "policy" / "bouncer.yaml", encoding="utf-8") as fh:
        return PolicyDoc.model_validate(yaml.safe_load(fh))


@lru_cache(maxsize=1)
def controls() -> dict:
    doc = policy_doc()
    return {
        "secrets": SecretsControl(doc.controls.secrets, doc),
        "pii": PiiControl(doc.controls.pii, doc),
        "prompt_injection": InjectionHeuristicsControl(doc.controls.prompt_injection, doc),
        "output_safety": OutputSafetyControl(doc.controls.output_safety, doc),
    }


def ctx(clearance: str = "internal", canary: str | None = None) -> ScanContext:
    return ScanContext(policy=None, principal=Principal("test-agent", "test", clearance), canary=canary)  # type: ignore[arg-type]


def segment(text: str, role: str = "user", tool: str = "web.fetch", direction: str | None = None) -> Segment:
    source = role if role in ("user", "system", "assistant") else f"{role}:{tool}"
    return Segment(text, direction or DIRECTION[role], source, role in ("system", "assistant"), (), tool if ":" in source else None)


def run(
    text: str,
    role: str = "user",
    control: str | object | None = None,
    obfuscation: ObfuscationCfg | None = None,
    context: ScanContext | None = None,
    direction: str | None = None,
) -> tuple[str, list[Finding]]:
    """prepare() + one control (or all four) the way the pipeline does it. Returns (clean_text, findings)."""
    obf = obfuscation if obfuscation is not None else policy_doc().controls.obfuscation
    seg = segment(text, role, direction=direction)
    clean, views, findings = prepare(seg, obf)
    seg_clean = Segment(clean, seg.direction, seg.source, seg.trusted, seg.location, seg.tool)
    if control is None:
        chosen = list(controls().values())
    elif isinstance(control, str):
        chosen = [controls()[control]]
    else:
        chosen = [control]
    for c in chosen:
        if c.applies_to(seg_clean):
            findings.extend(c.scan(seg_clean, views, context or ctx()))
    return clean, findings


def ids(findings: list[Finding]) -> set[str]:
    return {f.id for f in findings}


def redact(text: str, findings: list[Finding]) -> str:
    """Same replacement the pipeline applies for REDACT findings with a span."""
    from bouncer.core import Action

    spans = sorted({(f.span[0], f.span[1], f.rule) for f in findings if f.span and f.action == Action.REDACT})
    out, pos = [], 0
    for s, e, rule in spans:
        if s < pos:
            continue
        out.append(text[pos:s])
        out.append(f"[REDACTED:{rule}]")
        pos = e
    out.append(text[pos:])
    return "".join(out)
