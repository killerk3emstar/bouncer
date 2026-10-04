"""Core types shared by the pipeline and every control.

A request is split into Segments (one per piece of text: a user message, a tool result,
tool-call arguments, a tool definition, model output). Each Segment is prepared into Views
(the raw text plus normalized and decoded copies) and every enabled control scans the views
and returns Findings. The pipeline turns findings into one decision.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any, ClassVar, Literal

if TYPE_CHECKING:
    from bouncer.policy.compiled import CompiledPolicy


class Action(IntEnum):
    """Decision actions, ordered from weakest to strongest."""

    ALLOW = 0
    LOG = 1
    REDACT = 2
    REQUIRE_APPROVAL = 3
    BLOCK = 4

    @classmethod
    def parse(cls, value: str | Action) -> Action:
        if isinstance(value, Action):
            return value
        return cls[str(value).strip().upper()]

    def __str__(self) -> str:
        return self.name.lower()

    @property
    def label(self) -> str:
        return self.name.lower()


Direction = Literal["input", "output", "tool_call", "tool_result", "tool_definition"]
Tier = Literal["T0", "T1", "T2"]
Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITY_ORDER: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

Clearance = Literal["public", "internal", "confidential", "restricted"]
CLEARANCE_ORDER: dict[str, int] = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


@dataclass(slots=True)
class Segment:
    """One piece of text that crosses the gateway.

    source examples: "user", "system", "assistant", "tool_result:web.fetch",
    "tool_call:mail.send", "tool_definition:kb.search".
    location is where the text lives in the request/response body, so the pipeline can write
    a redacted version back, e.g. ("messages", 3, "content") or ("choices", 0, "message", "content").
    """

    text: str
    direction: Direction
    source: str
    trusted: bool = True
    location: tuple[Any, ...] = ()
    tool: str | None = None

    @property
    def role(self) -> str:
        return self.source.split(":", 1)[0]

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass(slots=True)
class View:
    """A version of a segment's text that controls scan.

    kind: "raw" (the text that is forwarded; offsets equal segment offsets),
          "normalized" (NFKC, homoglyphs folded, invisible characters removed; offsets not mappable),
          "decoded:base64" / "decoded:hex" / "decoded:url" (a decoded blob found in the raw text).
    span: for decoded views, the [start, end) of the encoded blob in the raw text, so a finding in the
          decoded copy can redact the whole blob. None for normalized views.
    """

    text: str
    kind: str = "raw"
    span: tuple[int, int] | None = None

    @property
    def exact(self) -> bool:
        return self.kind == "raw"


# MITRE ATLAS techniques for findings whose control does not set its own (checked against
# mitre-atlas/atlas-data dist/ATLAS.yaml, version 5.6.0). Key: "<control>.<rule>" first, then "<control>".
FINDING_ATLAS: dict[str, list[str]] = {
    "auth": ["AML.T0012"],  # Valid Accounts
    "tool_governance": ["AML.T0053"],  # AI Agent Tool Invocation
    # Exfiltration via AI Agent Tool Invocation
    "tool_governance.recipient_domain": ["AML.T0086", "AML.T0053"],
    "tool_governance.forbidden_field": ["AML.T0086", "AML.T0053"],
    "tool_governance.lethal_trifecta": ["AML.T0086", "AML.T0053"],
    "tool_governance.exfiltration": ["AML.T0086", "AML.T0053"],
    "budgets": ["AML.T0034"],  # Cost Harvesting
    "budgets.tokens_per_minute": ["AML.T0034", "AML.T0029"],  # + Denial of AI Service
    "budgets.max_input_tokens": ["AML.T0034.001", "AML.T0029"],  # Resource-Intensive Queries
    "budgets.max_steps": ["AML.T0034.002"],  # Agentic Resource Consumption
    "loops": ["AML.T0034.002"],
    "mcp_pinning": ["AML.T0109", "AML.T0110"],  # AI Supply Chain Rug Pull, AI Agent Tool Poisoning
    "supply_chain.mcp_server_not_allowed": ["AML.T0010.005"],  # AI Supply Chain Compromise: AI Agent Tool
    "supply_chain.model_source_not_allowed": ["AML.T0010.003"],  # AI Supply Chain Compromise: Model
    "supply_chain.trust_remote_code": ["AML.T0011.000"],  # Unsafe AI Artifacts
    "supply_chain.unsafe_weights_format": ["AML.T0011.000"],
    "prompt_injection": ["AML.T0051"],  # LLM Prompt Injection (T1 and T2 findings; T0 sets .000 / .001)
    "output_safety.canary": ["AML.T0056"],  # Extract LLM System Prompt
    "harmful_content": ["AML.T0048.000"],  # External Harms: Financial Harm
}


@dataclass(slots=True)
class Finding:
    """One thing a control detected. id = "<control>.<rule>"."""

    control: str
    rule: str
    tier: Tier = "T0"
    severity: Severity = "medium"
    action: Action = Action.BLOCK
    score: float = 1.0
    message: str = ""  # what was found, why it matters, what to do next
    span: tuple[int, int] | None = None  # in Segment.text (raw view); used for redaction
    evidence: str | None = None  # masked, never the raw secret
    owasp_llm: list[str] = field(default_factory=list)
    owasp_agentic: list[str] = field(default_factory=list)
    atlas: list[str] = field(default_factory=list)
    signature_id: str | None = None
    view: str = "raw"
    # Filled by the pipeline:
    direction: str = ""
    source: str = ""
    location: tuple[Any, ...] = ()
    monitor: bool = False  # control (or policy) in monitor mode: recorded, not enforced
    effective_action: Action | None = None

    def __post_init__(self) -> None:
        if not self.atlas:
            self.atlas = list(FINDING_ATLAS.get(f"{self.control}.{self.rule}") or FINDING_ATLAS.get(self.control) or [])

    @property
    def id(self) -> str:
        return f"{self.control}.{self.rule}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "control": self.control,
            "rule": self.rule,
            "tier": self.tier,
            "severity": self.severity,
            "score": round(float(self.score), 4),
            "action": self.action.label,
            "effective_action": (self.effective_action or self.action).label,
            "monitor": self.monitor,
            "message": self.message,
            "reason": self.message,
            "direction": self.direction,
            "source": self.source,
            "span": list(self.span) if self.span else None,
            "evidence": self.evidence,
            "view": self.view,
            "owasp_llm": self.owasp_llm,
            "owasp_agentic": self.owasp_agentic,
            "atlas": self.atlas,
            "signature_id": self.signature_id,
        }


@dataclass(slots=True)
class Principal:
    id: str
    team: str
    data_clearance: str = "internal"
    models: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    profile: str | None = None
    via: str | None = None  # the agent that called on this principal's behalf (delegation)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "team": self.team}
        if self.via:
            out["via"] = self.via
        return out


@dataclass(slots=True)
class ScanContext:
    """What a control may look at besides the text itself."""

    policy: CompiledPolicy
    principal: Principal
    route: str = "openai.chat"  # openai.chat | mcp.call | mcp.list | guard.check
    session_id: str = ""
    profile: str = "balanced"
    model: str | None = None
    canary: str | None = None  # canary token injected into the system prompt for this request
    extra: dict[str, Any] = field(default_factory=dict)


class Control:
    """Base class for text controls (T0).

    A control is built once per policy version from its config section (`cfg`, a pydantic model
    from bouncer.policy.schema) and must be immutable afterwards, so hot reload can swap policies
    atomically. scan() must be pure and fast (target p95 < 2 ms for a 2 KB segment).
    """

    id: ClassVar[str] = ""
    owasp_llm: ClassVar[list[str]] = []
    owasp_agentic: ClassVar[list[str]] = []

    def __init__(self, cfg: Any, policy_doc: Any) -> None:
        self.cfg = cfg
        self.policy_doc = policy_doc

    def applies_to(self, segment: Segment) -> bool:
        directions = getattr(self.cfg, "directions", None)
        return directions is None or segment.direction in directions

    def scan(self, segment: Segment, views: list[View], ctx: ScanContext) -> list[Finding]:
        raise NotImplementedError


def mask(value: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Mask a sensitive value for evidence: keep a short prefix and suffix, star the rest."""
    if len(value) <= keep_start + keep_end + 2:
        return value[:1] + "*" * max(len(value) - 1, 0)
    return value[:keep_start] + "*" * (len(value) - keep_start - keep_end) + value[-keep_end:]
