"""Compiled, immutable policy objects.

A CompiledPolicy is built once per policy file version: it validates the YAML, builds one variant
per strictness profile, and instantiates the text controls of each variant. Hot reload swaps the
whole object atomically; requests already in flight keep the version they started with.
"""

from __future__ import annotations

import hashlib
import importlib
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from bouncer.core import Control, Principal
from bouncer.policy.profiles import apply_profile
from bouncer.policy.schema import PolicyDoc

log = logging.getLogger("bouncer.policy")

# Text controls in scan order: (control id, module, class, accessor for its config section).
TEXT_CONTROLS: list[tuple[str, str, str]] = [
    ("secrets", "bouncer.controls.secrets", "SecretsControl"),
    ("pii", "bouncer.controls.pii", "PiiControl"),
    ("prompt_injection", "bouncer.controls.injection_heuristics", "InjectionHeuristicsControl"),
    ("signatures", "bouncer.controls.signatures", "SignaturesControl"),
    ("output_safety", "bouncer.controls.output_safety", "OutputSafetyControl"),
]

# Every control the gateway knows about, for the dashboard and coverage (id -> OWASP mapping).
CONTROL_CATALOG: dict[str, dict[str, Any]] = {
    "auth": {"title": "Agent authentication and model/tool allowlists", "owasp_llm": ["LLM06"], "owasp_agentic": ["ASI03"], "tier": "T0"},
    "secrets": {"title": "Secrets detection and redaction", "owasp_llm": ["LLM02"], "owasp_agentic": ["ASI03"], "tier": "T0"},
    "pii": {"title": "PII detection with checksum validation", "owasp_llm": ["LLM02"], "owasp_agentic": [], "tier": "T0"},
    "obfuscation": {"title": "Normalization and obfuscation detection", "owasp_llm": ["LLM01"], "owasp_agentic": ["ASI01"], "tier": "T0"},
    "prompt_injection": {"title": "Prompt injection (heuristics T0, classifier T1, judge T2)", "owasp_llm": ["LLM01"], "owasp_agentic": ["ASI01", "ASI06"], "tier": "T0/T1/T2"},
    "tool_governance": {"title": "Tool allowlists, argument limits, lethal trifecta, goal alignment", "owasp_llm": ["LLM06", "LLM02"], "owasp_agentic": ["ASI02", "ASI01"], "tier": "T0/T2"},
    "budgets": {"title": "Budgets, rate limits and model downgrade", "owasp_llm": ["LLM10"], "owasp_agentic": ["ASI08"], "tier": "T0"},
    "loops": {"title": "Loop and runaway detection with circuit breaker", "owasp_llm": ["LLM10"], "owasp_agentic": ["ASI08"], "tier": "T0"},
    "output_safety": {"title": "Output safety: markdown exfiltration, HTML, canary", "owasp_llm": ["LLM05", "LLM02", "LLM07"], "owasp_agentic": [], "tier": "T0"},
    "signatures": {"title": "Historical attack signatures (signed feed)", "owasp_llm": ["LLM01", "LLM03", "LLM05"], "owasp_agentic": ["ASI04", "ASI05"], "tier": "T0"},
    "supply_chain": {"title": "Supply chain: model sources, trust_remote_code, MCP server allowlist", "owasp_llm": ["LLM03"], "owasp_agentic": ["ASI04"], "tier": "T0"},
    "mcp_pinning": {"title": "MCP tool definition pinning (rug pull detection)", "owasp_llm": ["LLM03"], "owasp_agentic": ["ASI04"], "tier": "T0"},
    "approvals": {"title": "Human approval for risky actions", "owasp_llm": ["LLM06"], "owasp_agentic": ["ASI09"], "tier": "-"},
}


@dataclass
class PolicyVariant:
    profile: str
    doc: PolicyDoc
    controls: dict[str, Control]
    unavailable: dict[str, str] = field(default_factory=dict)  # control id -> import/build error


@dataclass
class CompiledPolicy:
    doc: PolicyDoc
    text: str
    version: str
    loaded_at: float
    source_path: str
    variants: dict[str, PolicyVariant]
    keys: dict[str, str]  # api key -> principal id

    @property
    def profile(self) -> str:
        return self.doc.profile

    @property
    def mode(self) -> str:
        return self.doc.defaults.mode

    def variant(self, profile: str | None = None) -> PolicyVariant:
        return self.variants[profile or self.doc.profile]

    def principal(self, principal_id: str) -> Principal | None:
        p = self.doc.principals.get(principal_id)
        if p is None:
            return None
        return Principal(
            id=principal_id,
            team=p.team,
            data_clearance=p.data_clearance,
            models=list(p.models),
            tools=list(p.tools),
            profile=p.profile,
        )

    def principal_for_key(self, key: str | None) -> Principal | None:
        if not key:
            return None
        pid = self.keys.get(key)
        return self.principal(pid) if pid else None

    def profile_for(self, principal: Principal) -> str:
        return principal.profile or self.doc.profile

    def info(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "profile": self.doc.profile,
            "mode": self.doc.defaults.mode,
            "fail_mode": self.doc.defaults.fail_mode,
            "loaded_at": self.loaded_at,
            "path": self.source_path,
        }


def policy_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()[:16]


def _control_cfg(doc: PolicyDoc, control_id: str) -> Any:
    return getattr(doc.controls, control_id, None)


def build_variant(doc: PolicyDoc, profile: str, shared: dict[str, Any]) -> PolicyVariant:
    vdoc = apply_profile(doc, profile)
    controls: dict[str, Control] = {}
    unavailable: dict[str, str] = {}
    for cid, module, cls_name in TEXT_CONTROLS:
        cfg = _control_cfg(vdoc, cid)
        if cfg is None or not getattr(cfg, "enabled", True):
            continue
        try:
            cls = getattr(importlib.import_module(module), cls_name)
            if cid == "signatures":
                controls[cid] = cls(cfg, vdoc, store=shared.get("feed_store"))
            else:
                controls[cid] = cls(cfg, vdoc)
        except ModuleNotFoundError as exc:
            log.warning("control %s unavailable: %s", cid, exc)
            unavailable[cid] = f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # a broken control must not take the gateway down
            log.exception("control %s unavailable", cid)
            unavailable[cid] = f"{type(exc).__name__}: {exc}"
    return PolicyVariant(profile=profile, doc=vdoc, controls=controls, unavailable=unavailable)


def compile_policy(doc: PolicyDoc, text: str, source_path: str, shared: dict[str, Any] | None = None) -> CompiledPolicy:
    shared = shared if shared is not None else {}
    variants = {p: build_variant(doc, p, shared) for p in ("balanced", "strict", "permissive")}
    keys: dict[str, str] = {}
    for pid, p in doc.principals.items():
        key = os.environ.get(p.key_env)
        if key:
            keys[key] = pid
    return CompiledPolicy(
        doc=doc,
        text=text,
        version=policy_hash(text),
        loaded_at=time.time(),
        source_path=source_path,
        variants=variants,
        keys=keys,
    )
