"""Pydantic schema for policy/bouncer.yaml.

Unknown keys are rejected (extra="forbid"), so a typo in the policy fails validation with a
line-numbered error instead of silently disabling a control.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ActionName = Literal["allow", "log", "redact", "require_approval", "block"]
DirectionName = Literal["input", "output", "tool_call", "tool_result", "tool_definition"]
ProfileName = Literal["permissive", "balanced", "strict"]
ModeName = Literal["enforce", "monitor"]
ClearanceName = Literal["public", "internal", "confidential", "restricted"]
PiiEntity = Literal["EMAIL", "PHONE", "PESEL", "NIP", "IBAN", "CREDIT_CARD"]

ALL_DIRECTIONS: list[DirectionName] = ["input", "output", "tool_call", "tool_result", "tool_definition"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Defaults(Strict):
    mode: ModeName = "enforce"
    fail_mode: Literal["closed", "open"] = "closed"
    block_response: Literal["error", "message"] = "error"


class Upstream(Strict):
    base_url: str
    local: bool = False
    api_key_env: str | None = None


class Price(Strict):
    input: float = Field(0.0, ge=0)
    output: float = Field(0.0, ge=0)


class ModelCfg(Strict):
    upstream: str
    upstream_model: str | None = None  # name at the upstream when it differs from the key
    price_per_1m_tokens: Price = Price()
    gpu_usd_per_second: float = Field(0.0, ge=0)
    max_concurrency: int | None = Field(None, ge=1)


class PrincipalCfg(Strict):
    key_env: str
    team: str
    data_clearance: ClearanceName = "internal"
    models: list[str] = []
    tools: list[str] = []
    profile: ProfileName | None = None
    # agents this principal may call on behalf of (X-Bouncer-On-Behalf-Of); permissions become the intersection
    may_act_for: list[str] = []


class TeamBudget(Strict):
    usd_per_day: float | None = Field(None, ge=0)
    tokens_per_minute: int | None = Field(None, ge=0)
    gpu_seconds_per_hour: float | None = Field(None, ge=0)


class SessionBudget(Strict):
    max_steps: int | None = Field(25, ge=1)
    max_usd: float | None = Field(None, ge=0)
    max_identical_tool_calls: int | None = Field(3, ge=1)
    loop_window_seconds: int = Field(120, ge=1)
    loop_cooldown_seconds: int = Field(60, ge=0)


class RequestLimits(Strict):
    max_input_tokens: int | None = Field(None, ge=1)
    max_output_tokens: int | None = Field(None, ge=1)


class OnExceed(Strict):
    action: Literal["block", "downgrade", "log"] = "block"
    downgrade_to: str | None = None
    hard_limit_action: Literal["block", "log"] = "block"


class Budgets(Strict):
    enabled: bool = True
    mode: ModeName | None = None
    teams: dict[str, TeamBudget] = {}
    sessions: SessionBudget = SessionBudget()
    requests: RequestLimits = RequestLimits()
    on_exceed: OnExceed = OnExceed()


# --------------------------------------------------------------------------- controls


class ControlCfg(Strict):
    enabled: bool = True
    mode: ModeName | None = None  # None = inherit defaults.mode


class EntropyCfg(Strict):
    enabled: bool = True
    min_length: int = Field(24, ge=8)
    min_bits_per_char: float = Field(4.2, ge=0)
    action: ActionName | None = None  # None = same as the secrets action


class SecretsCfg(ControlCfg):
    directions: list[DirectionName] = ["input", "output", "tool_call", "tool_result"]
    action: ActionName = "redact"
    rules: Literal["builtin"] | list[str] = "builtin"  # "builtin" or a list of builtin rule ids to enable
    entropy: EntropyCfg = EntropyCfg()
    overrides: dict[str, ActionName] = {}  # rule id -> action
    allow_values: list[str] = []  # exact values never reported (e.g. documented example keys)


class PiiCfg(ControlCfg):
    directions: list[DirectionName] = ["input", "output", "tool_result"]
    entities: dict[PiiEntity, ActionName] = {}
    output_visible_for_clearance: list[ClearanceName] = []
    # PII sent to a model whose upstream is not local: entities configured as redact (or stronger)
    # are enforced even for cleared principals. off = clearance applies to every upstream.
    external_models: Literal["enforce", "off"] = "enforce"
    # e-mail addresses at these domains (and subdomains) are business contacts, not customer PII
    internal_domains: list[str] = []


class ObfuscationCfg(ControlCfg):
    strip_invisible: bool = True
    unicode_tag_chars: ActionName = "block"
    homoglyphs: bool = True
    decode: list[Literal["base64", "hex", "url"]] = ["base64", "hex", "url"]
    max_decode_depth: int = Field(2, ge=0, le=5)


class HeuristicsCfg(Strict):
    enabled: bool = True
    action: ActionName = "block"


class ClassifierCfg(Strict):
    enabled: bool = True
    block_above: float = Field(0.98, ge=0, le=1)
    escalate_above: float = Field(0.50, ge=0, le=1)

    @model_validator(mode="after")
    def _order(self) -> ClassifierCfg:
        if self.escalate_above > self.block_above:
            raise ValueError("escalate_above must be <= block_above")
        return self


class JudgeThresholds(Strict):
    enabled: bool = True
    block_above: float = Field(0.85, ge=0, le=1)
    approval_above: float = Field(0.60, ge=0, le=1)

    @model_validator(mode="after")
    def _order(self) -> JudgeThresholds:
        if self.approval_above > self.block_above:
            raise ValueError("approval_above must be <= block_above")
        return self


class PromptInjectionCfg(ControlCfg):
    apply_to: list[Literal["user", "system", "tool_result", "tool_definition", "tool_call", "memory_write"]] = [
        "user",
        "tool_result",
        "tool_definition",
    ]
    heuristics: HeuristicsCfg = HeuristicsCfg()
    classifier: ClassifierCfg = ClassifierCfg()
    judge: JudgeThresholds = JudgeThresholds()
    escalate_non_english: bool = True


class TrifectaCfg(Strict):
    enabled: bool = True
    action: ActionName = "require_approval"


class GoalAlignmentCfg(Strict):
    enabled: bool = True
    apply_to: Literal["side_effect_tools", "all_tools"] = "side_effect_tools"
    block_above: float = Field(0.60, ge=0, le=1)  # P(misaligned)
    approval_above: float | None = Field(None, ge=0, le=1)  # P(misaligned) that needs a human
    exfiltration_approval_above: float = Field(0.80, ge=0, le=1)  # P(exfiltration = yes)


class ToolArgRule(Strict):
    to_domains_allow: list[str] | None = None
    recipient_fields: list[str] = ["to", "cc", "bcc"]
    forbid_fields: list[str] = []
    action: ActionName = "block"
    max_amount: float | None = Field(None, ge=0)
    amount_field: str = "amount"
    above_max: ActionName = "require_approval"
    scan_with_signatures: bool = False


class ToolGovernanceCfg(ControlCfg):
    side_effect_tools: list[str] = []
    untrusted_source_tools: list[str] = []
    sensitive_source_tools: list[str] = []
    memory_write_tools: list[str] = []  # content these tools persist is scanned like untrusted input
    unknown_tool: ActionName = "block"
    lethal_trifecta: TrifectaCfg = TrifectaCfg()
    goal_alignment: GoalAlignmentCfg = GoalAlignmentCfg()
    arguments: dict[str, ToolArgRule] = {}


class MarkdownLinksCfg(Strict):
    allow_domains: list[str] = []
    images: ActionName = "redact"
    links: ActionName = "redact"


class CanaryCfg(Strict):
    enabled: bool = True
    action: ActionName = "block"


class OutputSafetyCfg(ControlCfg):
    # output: every check; tool_result and input: only data-carrying markdown images (removed from tool results, logged in user messages)
    directions: list[DirectionName] = ["output", "tool_result", "input"]
    markdown_links: MarkdownLinksCfg = MarkdownLinksCfg()
    html: Literal["strip", "block", "log", "allow"] = "strip"
    canary: CanaryCfg = CanaryCfg()


class SignaturesCfg(ControlCfg):
    feed: str = "signatures/feed.json"
    public_key: str | None = "signatures/feed.pub"
    require_signature: bool = True
    refresh_seconds: int = Field(30, ge=1)
    action: ActionName = "block"


class McpSupplyCfg(Strict):
    servers_allow: list[str] = []
    pin_tool_definitions: bool = True


class SupplyChainCfg(ControlCfg):
    model_sources_allow: list[str] = []
    block_trust_remote_code: bool = True
    require_safetensors: bool = True
    mcp: McpSupplyCfg = McpSupplyCfg()


class HarmfulContentCfg(ControlCfg):
    action: ActionName = "block"  # strong T0 signal: the harmful aim is explicit (concealment, attack artefact)
    judge: JudgeThresholds = JudgeThresholds(block_above=0.85, approval_above=0.85)  # weak signal: asked to T2
    categories: list[Literal["financial_crime", "fraud", "cyberattack", "violence", "self_harm"]] = [
        "financial_crime", "fraud", "cyberattack", "violence", "self_harm"]


class Controls(Strict):
    secrets: SecretsCfg | None = None
    pii: PiiCfg | None = None
    obfuscation: ObfuscationCfg | None = None
    prompt_injection: PromptInjectionCfg | None = None
    tool_governance: ToolGovernanceCfg | None = None
    output_safety: OutputSafetyCfg | None = None
    signatures: SignaturesCfg | None = None
    supply_chain: SupplyChainCfg | None = None
    harmful_content: HarmfulContentCfg | None = None


# --------------------------------------------------------------------------- judge, audit


class JudgeQuestion(Strict):
    type: Literal["noul", "choice", "score"]
    instructions: str | None = None
    criteria: dict[str, str] | list[str] | None = None


class JudgeCfg(Strict):
    backend: Literal["clef-mlx", "ollama-guard", "fake", "none"] = "fake"
    url: str = "http://localhost:8701"
    timeout_ms: int = Field(4000, ge=50)
    on_timeout: Literal["default", "closed", "open"] = "default"
    cache_ttl_seconds: int = Field(900, ge=0)
    max_concurrency: int = Field(1, ge=1)
    allow_external: bool = False
    questions: dict[str, JudgeQuestion] = {}


class AuditCfg(Strict):
    path: str = "data/audit.jsonl"
    hash_chain: bool = True
    excerpt_chars: int = Field(300, ge=0, le=5000)
    retention_days: int = Field(30, ge=1)


class ApprovalsCfg(Strict):
    enabled: bool = True
    ttl_seconds: int = Field(600, ge=1)


class A2AAgentCfg(Strict):
    url: str  # JSON-RPC endpoint of the target agent (A2A message/send)
    card_url: str | None = None  # agent card; None = <origin of url>/.well-known/agent.json
    allowed_callers: list[str] = []  # principal ids that may send messages to this agent
    description: str | None = None


class A2ACfg(Strict):
    enabled: bool = True
    max_message_chars: int = Field(20000, ge=1)  # text of all parts of one message, either direction
    timeout_seconds: float = Field(30.0, gt=0)
    agents: dict[str, A2AAgentCfg] = {}


class PolicyDoc(Strict):
    version: int = 1
    profile: ProfileName = "balanced"
    defaults: Defaults = Defaults()
    upstreams: dict[str, Upstream] = {}
    models: dict[str, ModelCfg] = {}
    principals: dict[str, PrincipalCfg] = {}
    budgets: Budgets | None = Budgets()
    controls: Controls = Controls()
    judge: JudgeCfg = JudgeCfg()
    audit: AuditCfg = AuditCfg()
    approvals: ApprovalsCfg = ApprovalsCfg()
    a2a: A2ACfg = A2ACfg()

    @model_validator(mode="after")
    def _references(self) -> PolicyDoc:
        errors: list[str] = []
        for name, m in self.models.items():
            if m.upstream not in self.upstreams:
                errors.append(f"models.{name}.upstream: unknown upstream '{m.upstream}'")
        for pid, p in self.principals.items():
            for m in p.models:
                if m not in self.models:
                    errors.append(f"principals.{pid}.models: unknown model '{m}'")
            for other in p.may_act_for:
                if other not in self.principals:
                    errors.append(f"principals.{pid}.may_act_for: unknown principal '{other}'")
        for aid, agent in self.a2a.agents.items():
            for caller in agent.allowed_callers:
                if caller not in self.principals:
                    errors.append(f"a2a.agents.{aid}.allowed_callers: unknown principal '{caller}'")
            if not agent.url.startswith(("http://", "https://")):
                errors.append(f"a2a.agents.{aid}.url: must start with http:// or https://")
        if self.budgets and self.budgets.on_exceed.downgrade_to:
            if self.budgets.on_exceed.downgrade_to not in self.models:
                errors.append(
                    f"budgets.on_exceed.downgrade_to: unknown model '{self.budgets.on_exceed.downgrade_to}'"
                )
        if self.judge.allow_external is False:
            from urllib.parse import urlsplit

            host = (urlsplit(self.judge.url).hostname or "").lower()
            if host not in {"localhost", "127.0.0.1", "::1", "judge", "host.docker.internal"} and not host.endswith(
                ".local"
            ):
                errors.append(
                    f"judge.url: host '{host}' is not local and judge.allow_external is false; "
                    "prompts must not leave the organization"
                )
        if errors:
            raise ValueError("; ".join(errors))
        return self
