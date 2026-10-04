"""Decision pipeline: T0 deterministic controls -> T1 classifier -> T2 judge, tool governance,
budgets and loops. Used by the OpenAI proxy, the guard API and the MCP gateway.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from bouncer.audit import AuditLog
from bouncer.core import SEVERITY_ORDER, Action, Finding, Principal, ScanContext, Segment, View, mask
from bouncer.messages import (
    assistant_turns,
    call_hash,
    estimate_tokens,
    history_tool_call_hashes,
    history_tool_results,
    last_user_text,
    parse_args,
    request_text,
    resolve_tool_name,
    set_in,
)
from bouncer.policy.compiled import CompiledPolicy, PolicyVariant
from bouncer.policy.loader import PolicyManager
from bouncer.store import Store
from bouncer.telemetry import Telemetry

log = logging.getLogger("bouncer.pipeline")

REDACTION_CONTROLS = {"secrets", "pii"}


def new_trace_id() -> str:
    return "tr_" + secrets.token_hex(8)


def _now_ms() -> float:
    return time.perf_counter() * 1000.0


@dataclass
class RequestCtx:
    trace_id: str
    principal: Principal
    policy: CompiledPolicy
    variant: PolicyVariant
    route: str
    session_id: str
    model: str | None
    started_ms: float
    scan: ScanContext
    findings: list[Finding] = field(default_factory=list)
    latency: dict[str, float] = field(default_factory=lambda: {"t0": 0.0, "t1": 0.0, "t2": 0.0, "upstream": 0.0})
    judge: dict[str, Any] | None = None
    t1_scores: list[dict[str, Any]] = field(default_factory=list)
    escalated: bool = False
    t1_ran: bool = False
    user_request: str = ""
    downgraded_from: str | None = None
    approval_id: str | None = None
    excerpt: str = ""
    direction: str = "input"
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    status_code: int | None = None
    message: str | None = None
    input_key: str | None = None

    @property
    def doc(self):  # noqa: ANN201
        return self.variant.doc


@dataclass
class Decision:
    action: Action
    findings: list[Finding]
    status: int = 200
    code: str | None = None
    message: str = ""
    approval_id: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action >= Action.REQUIRE_APPROVAL


class Engine:
    def __init__(
        self,
        policies: PolicyManager,
        store: Store,
        audit: AuditLog,
        telemetry: Telemetry,
        classifier: Any = None,
        judge: Any = None,
        lang_detector: Any = None,
    ) -> None:
        self.policies = policies
        self.store = store
        self.audit = audit
        self.telemetry = telemetry
        self.classifier = classifier
        self.judge = judge
        self.is_english = lang_detector or (lambda text: True)
        self.normalize = _load_normalizer()

    # ------------------------------------------------------------------ context
    def begin(self, principal: Principal, route: str, session_id: str, model: str | None) -> RequestCtx:
        # sessions are namespaced by the calling agent, so one agent cannot taint, pause or spend another
        # agent's session by reusing its session id (a delegated call gets its own namespace too)
        key = principal_key(principal)
        if not session_id.startswith(key + "/"):
            session_id = f"{key}/{session_id}"
        policy = self.policies.current
        profile = policy.profile_for(principal)
        variant = policy.variant(profile)
        canary = None
        os_cfg = variant.doc.controls.output_safety
        if os_cfg is not None and os_cfg.enabled and os_cfg.canary.enabled:
            canary = "bc-" + secrets.token_hex(6)
        scan = ScanContext(
            policy=policy,
            principal=principal,
            route=route,
            session_id=session_id,
            profile=profile,
            model=model,
            canary=canary,
        )
        return RequestCtx(
            trace_id=new_trace_id(),
            principal=principal,
            policy=policy,
            variant=variant,
            route=route,
            session_id=session_id,
            model=model,
            started_ms=_now_ms(),
            scan=scan,
        )

    def known_tools(self, ctx: RequestCtx) -> set[str]:
        doc = ctx.doc
        tools = set(ctx.principal.tools)
        for p in doc.principals.values():
            tools.update(p.tools)
        tg = doc.controls.tool_governance
        if tg is not None:
            tools.update(tg.side_effect_tools, tg.untrusted_source_tools, tg.sensitive_source_tools, tg.arguments.keys())
        return tools

    # ------------------------------------------------------------------ helpers
    def _mode_for(self, ctx: RequestCtx, control: str) -> str:
        doc = ctx.doc
        cfg = getattr(doc.controls, control, None)
        if control in ("budgets", "loops") and doc.budgets is not None:
            cfg = doc.budgets
        mode = getattr(cfg, "mode", None) if cfg is not None else None
        return mode or doc.defaults.mode

    def finalize(self, ctx: RequestCtx, findings: list[Finding]) -> Action:
        """Apply monitor mode and the permissive profile, return the strongest effective action."""
        overall = Action.ALLOW
        for f in findings:
            eff = f.action
            if self._mode_for(ctx, f.control) == "monitor" and eff > Action.LOG:
                f.monitor = True
                eff = Action.LOG
            if ctx.scan.profile == "permissive" and eff > Action.LOG and SEVERITY_ORDER.get(f.severity, 2) < 4:
                eff = Action.LOG
                f.monitor = True
            f.effective_action = eff
            overall = max(overall, eff)
        return overall

    def _finding(self, control: str, rule: str, action: Action | str, message: str, **kw: Any) -> Finding:
        from bouncer.policy.compiled import CONTROL_CATALOG

        cat = CONTROL_CATALOG.get(control, {})
        kw.setdefault("owasp_llm", list(cat.get("owasp_llm", [])))
        kw.setdefault("owasp_agentic", list(cat.get("owasp_agentic", [])))
        return Finding(control=control, rule=rule, action=Action.parse(action), message=message, **kw)

    # ------------------------------------------------------------------ text scanning (T0)
    def scan_segment(self, ctx: RequestCtx, seg: Segment, use_cache: bool = True) -> tuple[str, list[Finding], list[View]]:
        """Run normalization and every T0 text control on one segment. Returns clean text, findings, views."""
        key = None
        if use_cache:
            key = (
                "t0",
                ctx.policy.version,
                ctx.scan.profile,
                ctx.principal.data_clearance,
                seg.direction,
                seg.source,
                seg.digest,
            )
            cached = self.store.cache_get(key)
            if cached is not None:
                clean, findings, views = cached
                return clean, [_copy_finding(f) for f in findings], views
        t = _now_ms()
        clean, views, findings = self.normalize(seg, ctx.doc.controls.obfuscation if _enabled(ctx.doc.controls.obfuscation) else None)
        seg_clean = Segment(clean, seg.direction, seg.source, seg.trusted, seg.location, seg.tool)
        for cid, control in ctx.variant.controls.items():
            try:
                if control.applies_to(seg_clean):
                    found = control.scan(seg_clean, views, ctx.scan)
                    if cid == "pii":
                        found = self._drop_internal_emails(ctx, clean, found)
                    findings.extend(found)
            except Exception as exc:  # a failing control applies fail_mode
                log.exception("control %s failed", cid)
                findings.append(self._fail_finding(ctx, cid, f"{type(exc).__name__}: {exc}"))
        for f in findings:
            f.direction = seg.direction
            f.source = seg.source
            f.location = seg.location
        ctx.latency["t0"] += _now_ms() - t
        if key is not None:
            self.store.cache_put(key, (clean, [_copy_finding(f) for f in findings], views))
        return clean, findings, views

    @staticmethod
    def _drop_internal_emails(ctx: RequestCtx, text: str, findings: list[Finding]) -> list[Finding]:
        """E-mail addresses at pii.internal_domains are business contacts (ops@bank.example), not PII."""
        pii = ctx.doc.controls.pii
        domains = [d.lower() for d in (pii.internal_domains if pii else [])]
        if not domains:
            return findings
        out = []
        for f in findings:
            if f.rule == "EMAIL" and f.span is not None:
                addr = text[f.span[0] : f.span[1]].lower()
                dom = addr.rsplit("@", 1)[-1] if "@" in addr else ""
                if dom and any(dom == d or dom.endswith("." + d) for d in domains):
                    continue
            out.append(f)
        return out

    def _fail_finding(self, ctx: RequestCtx, control: str, error: str) -> Finding:
        closed = ctx.doc.defaults.fail_mode == "closed"
        return self._finding(
            control,
            "control_error",
            Action.BLOCK if closed else Action.LOG,
            f"Control {control} failed ({error}). fail_mode is {ctx.doc.defaults.fail_mode}, so the request was "
            f"{'blocked' if closed else 'allowed and logged'}. Check the gateway logs.",
            severity="high",
        )

    # ------------------------------------------------------------------ budgets and loops (input side)
    def check_budget(self, ctx: RequestCtx, body: dict[str, Any]) -> list[Finding]:
        doc = ctx.doc
        b = doc.budgets
        out: list[Finding] = []
        if b is None or not b.enabled:
            return out
        team = ctx.principal.team
        tb = b.teams.get(team)
        sess = self.store.session(ctx.session_id)
        now = time.time()
        # circuit breaker from an earlier loop
        if sess.breaker_until > now:
            out.append(
                self._finding(
                    "loops",
                    "circuit_breaker_open",
                    Action.BLOCK,
                    f"Session {ctx.session_id[:12]} is paused for {int(sess.breaker_until - now)} s after a loop "
                    f"({sess.breaker_reason}). Wait for the cooldown or start a new session.",
                    severity="medium",
                )
            )
        steps = max(sess.steps, assistant_turns(body))
        if b.sessions.max_steps and steps >= b.sessions.max_steps:
            out.append(
                self._finding(
                    "loops",
                    "max_steps",
                    Action.BLOCK,
                    f"Session reached {steps} model calls (limit budgets.sessions.max_steps = {b.sessions.max_steps}). "
                    "The agent may be stuck; start a new session or raise the limit.",
                    severity="medium",
                )
            )
        text = request_text(body)
        est = estimate_tokens(text)
        if b.requests.max_input_tokens and est > b.requests.max_input_tokens:
            out.append(
                self._finding(
                    "budgets",
                    "max_input_tokens",
                    Action.BLOCK,
                    f"Request has about {est} input tokens (limit budgets.requests.max_input_tokens = "
                    f"{b.requests.max_input_tokens}). Shorten the context or summarize the history.",
                    severity="low",
                )
            )
        if tb and tb.tokens_per_minute is not None:
            used = self.store.tokens_last_minute(team)
            if used + est > tb.tokens_per_minute:
                out.append(
                    self._finding(
                        "budgets",
                        "tokens_per_minute",
                        Action.BLOCK,
                        f"Team {team} used {used} tokens in the last minute; this request (~{est}) would exceed "
                        f"{tb.tokens_per_minute}/min. Retry in a minute.",
                        severity="low",
                    )
                )
        if b.sessions.max_usd is not None and sess.usd >= b.sessions.max_usd:
            out.append(
                self._finding(
                    "budgets",
                    "session_usd",
                    Action.BLOCK,
                    f"Session spent ${sess.usd:.4f} (limit ${b.sessions.max_usd:.2f} per session). Start a new session "
                    "or raise budgets.sessions.max_usd.",
                    severity="medium",
                )
            )
        # team spend -> downgrade or block
        model = ctx.model
        if tb and tb.usd_per_day is not None and model:
            spent = self.store.team_spend_today(team)
            mcfg = doc.models.get(model)
            paid = mcfg is not None and (mcfg.price_per_1m_tokens.input > 0 or mcfg.price_per_1m_tokens.output > 0)
            if spent >= tb.usd_per_day and paid:
                target = b.on_exceed.downgrade_to
                if b.on_exceed.action == "downgrade" and target and target != model:
                    ctx.downgraded_from = model
                    ctx.model = target
                    ctx.scan.model = target
                    body["model"] = target
                    out.append(
                        self._finding(
                            "budgets",
                            "team_usd_per_day",
                            Action.LOG,
                            f"Team {team} spent ${spent:.4f} of ${tb.usd_per_day:.2f} today. Request downgraded from "
                            f"{model} to {target} (budgets.on_exceed.downgrade_to).",
                            severity="low",
                        )
                    )
                else:
                    act = Action.LOG if b.on_exceed.action == "log" else Action.BLOCK
                    out.append(
                        self._finding(
                            "budgets",
                            "team_usd_per_day",
                            act,
                            f"Team {team} spent ${spent:.4f} of ${tb.usd_per_day:.2f} today. Wait for the daily reset "
                            "or ask the budget owner to raise budgets.teams.{team}.usd_per_day.",
                            severity="medium",
                        )
                    )
        # local GPU time (applies to the model actually used, also after a downgrade)
        if tb and tb.gpu_seconds_per_hour is not None and ctx.model:
            mcfg = doc.models.get(ctx.model)
            up = doc.upstreams.get(mcfg.upstream) if mcfg else None
            if up is not None and up.local:
                gpu = self.store.gpu_seconds_last_hour(team)
                if gpu >= tb.gpu_seconds_per_hour:
                    act = Action.LOG if b.on_exceed.hard_limit_action == "log" else Action.BLOCK
                    out.append(
                        self._finding(
                            "budgets",
                            "gpu_seconds_per_hour",
                            act,
                            f"Team {team} used {gpu:.1f} s of local GPU time in the last hour (limit "
                            f"{tb.gpu_seconds_per_hour:.0f} s). The shared GPU is protected; retry later.",
                            severity="medium",
                        )
                    )
        return out

    # ------------------------------------------------------------------ input inspection
    async def inspect_input(self, ctx: RequestCtx, body: dict[str, Any]) -> Decision:
        from bouncer.messages import extract_input_segments

        doc = ctx.doc
        known = self.known_tools(ctx)
        tg = doc.controls.tool_governance if _enabled(doc.controls.tool_governance) else None
        untrusted_tools = set(tg.untrusted_source_tools) if tg else set()
        sensitive_tools = set(tg.sensitive_source_tools) if tg else set()
        ctx.user_request = last_user_text(body)

        findings: list[Finding] = list(self.check_budget(ctx, body))
        segments = extract_input_segments(body, known, untrusted_tools)
        cleaned: list[tuple[Segment, str, list[Finding]]] = []
        for seg in segments:
            clean, seg_findings, _views = self.scan_segment(ctx, seg)
            if seg.direction == "tool_definition":
                for f in seg_findings:
                    if f.control in REDACTION_CONTROLS and f.action == Action.REDACT:
                        f.action = Action.BLOCK
                        f.message += " Tool definitions cannot be rewritten in place, so the request was blocked; remove the value from the tool description."
            cleaned.append((seg, clean, seg_findings))
            findings.extend(seg_findings)

        self._enforce_pii_for_external_model(ctx, findings)

        # session taint from the history (stateless) and from the store
        for name in history_tool_results(body, known):
            if name in untrusted_tools:
                self.store.mark_taint(ctx.session_id, "untrusted", name)
            if name in sensitive_tools:
                self.store.mark_taint(ctx.session_id, "sensitive", name)
        if any(f.control == "pii" for f in findings):
            self.store.mark_taint(ctx.session_id, "sensitive", "pii in conversation")

        # T1 + T2 on untrusted segments, skipped when a deterministic rule already blocks the request
        pi = doc.controls.prompt_injection if _enabled(doc.controls.prompt_injection) else None
        if pi is not None and not self._enforced_block(ctx, findings):
            findings.extend(await self._semantic_injection(ctx, cleaned, pi))
        elif pi is not None:
            ctx.notes.append("semantic layers skipped: a deterministic control already blocks this request")
        hc = doc.controls.harmful_content if _enabled(doc.controls.harmful_content) else None
        if hc is not None and not self._enforced_block(ctx, findings):
            findings.extend(await self._semantic_harm(ctx, cleaned, hc))

        # an approved identical input passes its require_approval findings; the key is a hash of the raw
        # text and is never stored as text (the audit excerpt is taken after redaction, below)
        ctx.input_key = call_hash("input", request_text(body))
        if any(f.action == Action.REQUIRE_APPROVAL for f in findings):
            appr = self.store.approved(principal_key(ctx.principal), ctx.input_key, ctx.session_id)
            if appr is not None:
                for f in findings:
                    if f.action == Action.REQUIRE_APPROVAL:
                        f.action = Action.LOG
                        f.message += f" Approved by a human ({appr.id})."
        action = self.finalize(ctx, findings)
        # write back: invisible characters stripped and redactions applied
        for seg, clean, seg_findings in cleaned:
            redacted = apply_redactions(clean, [f for f in seg_findings if (f.effective_action or f.action) == Action.REDACT])
            if redacted != seg.text and seg.direction != "tool_definition":
                set_in(body, seg.location, redacted)
        # redact findings without a span cannot be applied in place
        for f in findings:
            if f.effective_action == Action.REDACT and f.span is None and f.control in REDACTION_CONTROLS and f.view != "raw":
                pass  # decoded-view findings carry the blob span; normalized-view ones are emitted as block by controls
        ctx.findings.extend(findings)
        ctx.excerpt = _safe_excerpt(body, cleaned, doc.audit.excerpt_chars)
        return self._decision(ctx, findings, action, phase="input")

    def audit_mask(self, ctx: RequestCtx, text: str, direction: str = "tool_call") -> str:
        """Text for the audit log, approvals and the judge: every secret and PII value masked, whatever the
        policy's enforcement directions and actions are. If a value was found only in a normalized or decoded
        form (no exact position), the text is withheld."""
        if not text:
            return text
        seg = Segment(text, direction, "audit", False, ())  # type: ignore[arg-type]
        clean, views, _ = self.normalize(seg, ctx.doc.controls.obfuscation if _enabled(ctx.doc.controls.obfuscation) else None)
        seg = Segment(clean, direction, "audit", False, ())  # type: ignore[arg-type]
        found: list[Finding] = []
        for cid in REDACTION_CONTROLS:
            control = ctx.variant.controls.get(cid)
            if control is None:
                continue
            try:
                found.extend(control.scan(seg, views, ctx.scan))
            except Exception:  # masking must never fail open into the log
                log.exception("audit masking with %s failed", cid)
                return "[withheld: masking failed]"
        if any(f.span is None for f in found):
            return f"[withheld: {', '.join(sorted({f.id for f in found if f.span is None}))} found in an encoded or normalized form]"
        return apply_redactions(clean, found)

    def _masked_args(self, ctx: RequestCtx, args_text: str) -> Any:
        masked = self.audit_mask(ctx, args_text or "")
        if masked.startswith("[withheld"):
            return masked
        return _mask_args(parse_args(masked))

    def _judge_enabled(self, ctx: RequestCtx) -> bool:
        """The judge is off when the policy says backend: none or the gateway overrides it to none."""
        if self.judge is None:
            return False
        backend = getattr(self.judge, "backend", None) or ctx.doc.judge.backend
        return backend != "none"

    def _enforced_block(self, ctx: RequestCtx, findings: list[Finding]) -> bool:
        """True when some finding will block regardless of later layers (not monitor, not permissive-capped)."""
        for f in findings:
            if f.action < Action.BLOCK or self._mode_for(ctx, f.control) == "monitor":
                continue
            if ctx.scan.profile == "permissive" and SEVERITY_ORDER.get(f.severity, 2) < 4:
                continue
            return True
        return False

    def _enforce_pii_for_external_model(self, ctx: RequestCtx, findings: list[Finding]) -> None:
        """Clearance lets a principal see PII, but PII still must not reach an external model provider."""
        pii = ctx.doc.controls.pii
        if pii is None or pii.external_models != "enforce" or not ctx.model:
            return
        mcfg = ctx.doc.models.get(ctx.model)
        up = ctx.doc.upstreams.get(mcfg.upstream) if mcfg else None
        if up is None or up.local:
            return
        for f in findings:
            if f.control != "pii" or f.direction not in ("input", "tool_result") or f.span is None:
                continue
            configured = Action.parse(pii.entities.get(f.rule, "log"))
            if configured >= Action.REDACT and f.action < configured:
                f.action = configured
                f.message = (
                    f"{f.rule} redacted before it reached {ctx.model}: the model provider is external "
                    f"(upstream {mcfg.upstream}), so the clearance of {ctx.principal.id} does not apply "
                    "(pii.external_models). Use a local model for work that needs customer identifiers."
                )

    async def _semantic_injection(
        self, ctx: RequestCtx, cleaned: list[tuple[Segment, str, list[Finding]]], pi: Any
    ) -> list[Finding]:
        out: list[Finding] = []
        roles = set(pi.apply_to)
        # the AI layers only ever see text with secrets and PII already replaced by [REDACTED:...] markers
        candidates = [
            (seg, apply_redactions(clean, [f for f in segf if f.control in REDACTION_CONTROLS and f.span is not None]), segf)
            for seg, clean, segf in cleaned
            if seg.role in roles and clean.strip() and not any(f.control == "prompt_injection" and f.action >= Action.BLOCK for f in segf)
        ]
        if not candidates:
            return out
        escalate: list[tuple[Segment, str, str, float | None]] = []
        # T1 classifier (English only), cached per text
        if pi.classifier.enabled and self.classifier is not None:
            todo, scores = [], {}
            for seg, clean, _ in candidates:
                cached = self.store.cache_get(("t1", getattr(self.classifier, "name", "t1"), _digest(clean)))
                if cached is not None:
                    scores[seg.digest] = cached
                else:
                    todo.append((seg, clean))
            if todo:
                t = _now_ms()
                try:
                    vals = await asyncio.get_running_loop().run_in_executor(
                        None, self.classifier.score, [c for _, c in todo]
                    )
                except Exception as exc:
                    log.exception("T1 classifier failed")
                    out.append(self._fail_finding(ctx, "prompt_injection", f"T1 classifier: {exc}"))
                    vals = [None] * len(todo)
                ctx.latency["t1"] += _now_ms() - t
                ctx.t1_ran = True
                for (seg, text), v in zip(todo, vals, strict=True):
                    if v is not None:
                        scores[seg.digest] = float(v)
                        self.store.cache_put(("t1", getattr(self.classifier, "name", "t1"), _digest(text)), float(v))
            for seg, clean, _ in candidates:
                score = scores.get(seg.digest)
                english = self.is_english(clean)
                ctx.t1_scores.append({"source": seg.source, "score": score, "english": english})
                if score is None:
                    continue
                if english and pi.classifier.block_above < 1.0 and score >= pi.classifier.block_above:
                    out.append(
                        self._finding(
                            "prompt_injection",
                            "classifier",
                            Action.BLOCK,
                            f"T1 classifier scored {describe_source(seg.source)} at {score:.2f} for prompt injection (block_above "
                            f"{pi.classifier.block_above}). Remove the instructions aimed at the assistant, or lower "
                            "the threshold if this is a false positive.",
                            tier="T1",
                            severity="high",
                            score=score,
                            direction=seg.direction,
                            source=seg.source,
                            location=seg.location,
                        )
                    )
                elif english and score >= pi.classifier.escalate_above:
                    escalate.append((seg, clean, "t1_grey_zone", score))
                elif not english and pi.escalate_non_english:
                    escalate.append((seg, clean, "non_english", score))
        else:
            for seg, clean, _ in candidates:
                if pi.escalate_non_english and not self.is_english(clean):
                    escalate.append((seg, clean, "non_english", None))
        # T2 judge on escalations
        if escalate:
            out.extend(await self._judge_injection(ctx, escalate, pi))
        return out

    async def _semantic_harm(self, ctx: RequestCtx, cleaned: list[tuple[Segment, str, list[Finding]]], hc: Any) -> list[Finding]:
        """Weak harm signals in user messages (a harm topic asked operationally, no defensive purpose) go to the
        T2 judge's `harm` question; strong ones were already blocked at T0 by the harmful_content control."""
        from bouncer.controls.harmful_content import CATEGORY_LABEL, assess

        out: list[Finding] = []
        question = ctx.doc.judge.questions.get("harm")
        for seg, clean, segf in cleaned:
            if seg.direction != "input" or seg.role != "user" or any(f.control == "harmful_content" for f in segf):
                continue
            text = apply_redactions(clean, [f for f in segf if f.control in REDACTION_CONTROLS and f.span is not None])
            sig = assess(text, list(hc.categories))
            if sig is None or sig.strength != "weak":
                continue
            atlas = ["AML.T0048.000"] if sig.category in ("financial_crime", "fraud") else ["AML.T0048.003"]
            if question is None or not hc.judge.enabled or not self._judge_enabled(ctx):
                out.append(self._finding(
                    "harmful_content", "signal", Action.LOG,
                    f"The message touches on {CATEGORY_LABEL[sig.category]} ({sig.why}); it needed a T2 review but the "
                    "judge or its harm question is disabled, so it was recorded only.",
                    tier="T0", severity="low", evidence=sig.evidence, atlas=atlas,
                    direction=seg.direction, source=seg.source, location=seg.location,
                ))
                continue
            ctx.escalated = True
            res = await self._judge_call(ctx, {"USER_MESSAGE": _clip(text, 2000)},
                                         {"harm": question.model_dump(exclude_none=True)}, "harm_signal")
            if res is None:
                continue
            if res.get("error"):
                out.append(self._judge_failure(ctx, "harmful_content", res["error"], seg))
                continue
            p_yes = float(((res.get("answers") or {}).get("harm") or {}).get("yes", 0.0))
            if p_yes >= hc.judge.block_above:
                act, verb = Action.BLOCK, "blocked"
            elif p_yes >= hc.judge.approval_above:
                act, verb = Action.REQUIRE_APPROVAL, "held for approval"
            else:
                continue
            out.append(self._finding(
                "harmful_content", "judge", act,
                f"T2 judge ({res.get('backend')}) rated the message as a request for help with "
                f"{CATEGORY_LABEL[sig.category]} with p={p_yes:.2f} (T0 signal: {sig.why}); {verb}. The assistant does "
                "not help with that; questions about detecting, preventing or reporting it are allowed.",
                tier="T2", severity="high", score=p_yes, evidence=sig.evidence, atlas=atlas,
                direction=seg.direction, source=seg.source, location=seg.location,
            ))
        return out

    async def _judge_injection(self, ctx: RequestCtx, escalate: list[tuple[Segment, str, str, float | None]], pi: Any) -> list[Finding]:
        out: list[Finding] = []
        questions = ctx.doc.judge.questions
        q = questions.get("injection")
        if not self._judge_enabled(ctx) or q is None or not pi.judge.enabled:
            for seg, _clean, reason, score in escalate:
                out.append(
                    self._finding(
                        "prompt_injection",
                        "grey_zone",
                        Action.LOG,
                        f"{describe_source(seg.source).capitalize()} needed a T2 review ({reason}) but the judge is disabled; recorded only.",
                        tier="T1",
                        severity="low",
                        score=score or 0.0,
                        direction=seg.direction,
                        source=seg.source,
                        location=seg.location,
                    )
                )
            return out
        ctx.escalated = True
        for seg, clean, reason, _score in escalate:
            # Clef latency grows with input length (measured 2.0 s at ~300 tokens, 4.1 s at ~1000 on M4 Pro).
            # A user message is a direct attack candidate (jailbreak question); anything else is untrusted
            # content that may carry instructions (injection question).
            if seg.role == "user" and "jailbreak" in questions:
                qid = "jailbreak"
                state = {"USER_MESSAGE": _clip(clean, 2000)}
            else:
                qid = "injection"
                state = None
            if state is not None:
                states = [state]
            else:
                # a long page is judged in overlapping windows: clipping it to the first 2000 characters let
                # padding push the payload out of the judge's view (reports/judge_attacks.md)
                req = _clip(self.audit_mask(ctx, ctx.user_request, "input"), 600)
                states = [{"USER_REQUEST": req, "UNTRUSTED_CONTENT": w} for w in _windows(clean, 2000, 200, 4)]
            p_yes, res = 0.0, None
            for st in states:
                r = await self._judge_call(ctx, st, {qid: questions[qid].model_dump(exclude_none=True)}, reason)
                if r is None:
                    continue
                if r.get("error"):
                    res = r
                    break
                p = float(((r.get("answers") or {}).get(qid) or {}).get("yes", 0.0))
                if res is None or p > p_yes:
                    p_yes, res = p, r
                if p_yes >= pi.judge.block_above:
                    break
            if res is None:
                continue
            if res.get("error"):
                out.append(self._judge_failure(ctx, "prompt_injection", res["error"], seg))
                continue
            if p_yes >= pi.judge.block_above:
                act, verb = Action.BLOCK, "blocked"
            elif p_yes >= pi.judge.approval_above:
                act, verb = Action.REQUIRE_APPROVAL, "held for approval"
            else:
                continue
            out.append(
                self._finding(
                    "prompt_injection",
                    "judge",
                    act,
                    f"T2 judge ({res.get('backend')}) rated {describe_source(seg.source)} as "
                    f"{'an attempt to bypass the assistant rules or extract its instructions' if qid == 'jailbreak' else 'an injection attempt'} with p={p_yes:.2f} "
                    f"(escalated: {reason}); {verb}. Review the content source before letting the agent act on it.",
                    tier="T2",
                    severity="high",
                    score=p_yes,
                    direction=seg.direction,
                    source=seg.source,
                    location=seg.location,
                )
            )
        return out

    async def _judge_call(self, ctx: RequestCtx, state: dict[str, Any], questions: dict[str, Any], reason: str) -> dict[str, Any] | None:
        t = _now_ms()
        try:
            res = await self.judge.decide(state, questions, reason)
        except Exception as exc:  # the client should not raise, but never trust that
            log.exception("judge call failed")
            res = None
            err = f"{type(exc).__name__}"
        else:
            err = None
        elapsed = _now_ms() - t
        ctx.latency["t2"] += elapsed
        info = _judge_result_dict(res) if res is not None else {"invoked": True, "error": err or "exception"}
        info.setdefault("reason", reason)
        info.setdefault("latency_ms", round(elapsed, 1))
        self.telemetry.judge_calls.labels(reason, str(bool(info.get("cached"))), str(info.get("error") or "")).inc()
        prev = ctx.judge
        if prev is None:
            ctx.judge = info
        else:
            prev.setdefault("calls", []).append(info)
            answers = dict(prev.get("answers") or {})
            answers.update(info.get("answers") or {})
            prev["answers"] = answers
        return info

    def _judge_failure(self, ctx: RequestCtx, control: str, error: str, seg: Segment | None) -> Finding:
        jc = ctx.doc.judge
        mode = jc.on_timeout if jc.on_timeout != "default" else ctx.doc.defaults.fail_mode
        act = Action.BLOCK if mode == "closed" else Action.LOG
        return self._finding(
            control,
            "judge_unavailable",
            act,
            f"T2 judge did not answer ({error}). fail_mode is {mode}, so this was "
            f"{'blocked' if act == Action.BLOCK else 'allowed and logged'}. Check the judge service on {jc.url}.",
            tier="T2",
            severity="medium",
            direction=seg.direction if seg else "",
            source=seg.source if seg else "",
        )

    # ------------------------------------------------------------------ output inspection
    def scan_output_text(self, ctx: RequestCtx, text: str, location: tuple[Any, ...] = ()) -> tuple[str, list[Finding]]:
        seg = Segment(text, "output", "assistant", True, location)
        clean, findings, _ = self.scan_segment(ctx, seg, use_cache=False)
        return clean, findings

    async def inspect_tool_calls(
        self, ctx: RequestCtx, body: dict[str, Any], tool_calls: list[dict[str, Any]], base_location: tuple[Any, ...] = ()
    ) -> list[Finding]:
        """Check tool calls the model wants the agent to run. Mutates arguments in place on redaction."""
        doc = ctx.doc
        known = self.known_tools(ctx)
        tg = doc.controls.tool_governance if _enabled(doc.controls.tool_governance) else None
        b = doc.budgets
        findings: list[Finding] = []
        history_hashes = history_tool_call_hashes(body, known)
        sess = self.store.session(ctx.session_id)
        for k, tc in enumerate(tool_calls):
            fn = tc.get("function") or {}
            wire = str(fn.get("name", ""))
            name = resolve_tool_name(wire, known)
            raw_args = fn.get("arguments")
            args = parse_args(raw_args)
            args_text = raw_args if isinstance(raw_args, str) else json.dumps(args, ensure_ascii=False)
            loc = (*base_location, k, "function", "arguments")
            seg = Segment(args_text or "", "tool_call", f"tool_call:{name}", False, loc, tool=name)
            clean, seg_findings, _ = self.scan_segment(ctx, seg, use_cache=False)
            # PII in tool arguments: the arguments reach the tool unchanged (rewriting an IBAN or a recipient would
            # break a legitimate call), so only entities set to block or require_approval act here, for example a
            # full card number in an e-mail body. Where other data may go is checked by the recipient rules and the
            # lethal trifecta; the audit log masks every value anyway.
            seg_findings = [f for f in seg_findings if f.control != "pii" or f.action >= Action.REQUIRE_APPROVAL]
            call_findings: list[Finding] = list(seg_findings)
            os_cfg = doc.controls.output_safety
            if (
                ctx.scan.canary
                and os_cfg is not None
                and os_cfg.enabled
                and os_cfg.canary.enabled
                and ctx.scan.canary in (args_text or "")
                and not any(f.id == "output_safety.canary" for f in call_findings)
            ):
                call_findings.append(
                    self._finding(
                        "output_safety",
                        "canary",
                        os_cfg.canary.action,
                        f"The arguments of {name} contain the canary token from the system prompt: the model is "
                        "leaking its instructions through a tool call. Review the conversation for a prompt-leak attempt.",
                        severity="critical",
                        owasp_llm=["LLM07"],
                    )
                )
            h = call_hash(name, args)
            record = {"tool": name, "wire_name": wire, "call_hash": h, "arguments": self._masked_args(ctx, args_text or "")}
            if tg is not None and name in tg.memory_write_tools:
                call_findings.extend(await self._scan_memory_write(ctx, name, args_text or "", loc))
            if tg is not None:
                call_findings.extend(self._tool_rules(ctx, tg, name, args, sess))
                if name in tg.side_effect_tools and tg.goal_alignment.enabled:
                    call_findings.extend(await self._goal_alignment(ctx, tg, name, args))
                elif tg.goal_alignment.enabled and tg.goal_alignment.apply_to == "all_tools":
                    call_findings.extend(await self._goal_alignment(ctx, tg, name, args))
            # loops
            if b is not None and b.enabled and b.sessions.max_identical_tool_calls:
                n_store = self.store.identical_calls(ctx.session_id, h, b.sessions.loop_window_seconds)
                n_hist = history_hashes.count(h)
                n = max(n_store, n_hist)
                if n >= b.sessions.max_identical_tool_calls:
                    sess.breaker_until = time.time() + b.sessions.loop_cooldown_seconds
                    sess.breaker_reason = f"{name} repeated {n + 1} times with identical arguments"
                    call_findings.append(
                        self._finding(
                            "loops",
                            "identical_tool_calls",
                            Action.BLOCK,
                            f"{name} was requested {n + 1} times with identical arguments within "
                            f"{b.sessions.loop_window_seconds} s (limit {b.sessions.max_identical_tool_calls}). "
                            f"The session is paused for {b.sessions.loop_cooldown_seconds} s; change the approach "
                            "instead of retrying.",
                            severity="medium",
                        )
                    )
            for f in call_findings:
                f.direction = "tool_call"
                f.source = f"tool_call:{name}"
                f.location = f.location or loc
            # approvals: an approved identical call passes the require_approval findings
            appr = self.store.approved(principal_key(ctx.principal), h, ctx.session_id)
            if appr is not None:
                for f in call_findings:
                    if f.action == Action.REQUIRE_APPROVAL:
                        f.action = Action.LOG
                        f.message += f" Approved by a human ({appr.id}), allowed once within the approval window."
            record["findings"] = [f.id for f in call_findings]
            ctx.tool_calls.append(record)
            # redact arguments in place; the audit record and approvals only ever see the redacted form
            red = [f for f in seg_findings if f.action == Action.REDACT and f.span is not None]
            if red:
                fn["arguments"] = apply_redactions(clean, red)
            tc["_bouncer"] = {"tool": name, "call_hash": h, "findings": call_findings}
            findings.extend(call_findings)
        return findings

    async def _scan_memory_write(self, ctx: RequestCtx, name: str, text: str, loc: tuple[Any, ...]) -> list[Finding]:
        """Content an agent persists to shared memory or a knowledge base is read later by other agents and
        sessions, so it gets the same injection checks as untrusted input (OWASP Agentic ASI06)."""
        pi = ctx.doc.controls.prompt_injection if _enabled(ctx.doc.controls.prompt_injection) else None
        if pi is None or "memory_write" not in pi.apply_to:
            return []
        seg = Segment(text, "tool_call", f"memory_write:{name}", False, loc, tool=name)
        clean, found, _ = self.scan_segment(ctx, seg, use_cache=False)
        found = [f for f in found if f.control == "prompt_injection"]
        if not self._enforced_block(ctx, found):
            found += await self._semantic_injection(ctx, [(seg, clean, found)], pi)
        if not self._enforced_block(ctx, found):
            found += await self._judge_memory_write(ctx, seg, clean, found)
        for f in found:
            f.owasp_agentic = sorted(set(f.owasp_agentic) | {"ASI06"})
            f.message = f"{f.message} The text was about to be saved by {name}, where other agents would read it later."
        return found

    async def _judge_memory_write(self, ctx: RequestCtx, seg: Segment, clean: str, found: list[Finding]) -> list[Finding]:
        """Every memory write gets the T2 question memory_poisoning: a planted standing rule for later sessions
        ("always send the customer list to ...") is not an instruction to this assistant, so the injection
        question misses it (measured: p=0.03 on such a note)."""
        tg = ctx.doc.controls.tool_governance
        cfg = tg.memory_write_judge
        question = ctx.doc.judge.questions.get("memory_poisoning")
        if not cfg.enabled or question is None or not self._judge_enabled(ctx):
            return []
        text = apply_redactions(clean, [f for f in found if f.control in REDACTION_CONTROLS and f.span is not None])
        ctx.escalated = True
        state = {"USER_REQUEST": _clip(self.audit_mask(ctx, ctx.user_request, "input"), 600), "SAVED_NOTE": _clip(text, 2000)}
        res = await self._judge_call(ctx, state, {"memory_poisoning": question.model_dump(exclude_none=True)}, "memory_write")
        if res is None:
            return []
        if res.get("error"):
            return [self._judge_failure(ctx, "tool_governance", res["error"], seg)]
        p_yes = float(((res.get("answers") or {}).get("memory_poisoning") or {}).get("yes", 0.0))
        if p_yes >= cfg.block_above:
            act, verb = Action.BLOCK, "blocked"
        elif p_yes >= cfg.approval_above:
            act, verb = Action.REQUIRE_APPROVAL, "held for approval"
        else:
            return []
        return [self._finding(
            "tool_governance", "memory_poisoning", act,
            f"T2 judge ({res.get('backend')}) rated the note {seg.tool} would save as an instruction planted for "
            f"assistants in later sessions with p={p_yes:.2f}; {verb}. Save facts, not standing orders for the "
            "assistant; ask a human to approve if the note is intended.",
            tier="T2", severity="high", score=p_yes, direction=seg.direction, source=seg.source,
            location=seg.location, owasp_agentic=["ASI06"],
        )]

    def _tool_rules(self, ctx: RequestCtx, tg: Any, name: str, args: Any, sess: Any) -> list[Finding]:
        out: list[Finding] = []
        principal = ctx.principal
        if name not in principal.tools:
            out.append(
                self._finding(
                    "tool_governance",
                    "unknown_tool",
                    tg.unknown_tool,
                    f"{principal.id} is not allowed to call {name} (principals.{principal.id}.tools). Add the tool to "
                    "the allowlist if this is intended.",
                    severity="high",
                )
            )
        rule = tg.arguments.get(name)
        if rule is not None and isinstance(args, dict):
            if rule.to_domains_allow is not None:
                external = []
                for fld in rule.recipient_fields:
                    for addr in _as_list(args.get(fld)):
                        dom = addr.rsplit("@", 1)[-1].strip().lower().rstrip(">") if "@" in addr else ""
                        if dom and not any(dom == d or dom.endswith("." + d) for d in rule.to_domains_allow):
                            external.append(f"{fld}={mask(addr, 2, len(dom) + 1)}")
                if external:
                    out.append(
                        self._finding(
                            "tool_governance",
                            "recipient_domain",
                            rule.action,
                            f"{name} to a domain outside {rule.to_domains_allow} ({', '.join(external)}). "
                            "Only internal recipients are allowed for this agent; ask a human to send it.",
                            severity="high",
                            evidence=", ".join(external),
                        )
                    )
            for fld in rule.forbid_fields:
                if args.get(fld):
                    out.append(
                        self._finding(
                            "tool_governance",
                            "forbidden_field",
                            rule.action,
                            f"{name} sets '{fld}', which the policy forbids (hidden copies were used to exfiltrate mail "
                            "in the postmark-mcp incident, 2025). Remove the field.",
                            severity="high",
                            evidence=f"{fld}={mask(str(args.get(fld)), 2, 4)}",
                        )
                    )
            if rule.max_amount is not None:
                amount = _to_float(args.get(rule.amount_field))
                if amount is not None and amount > rule.max_amount:
                    out.append(
                        self._finding(
                            "tool_governance",
                            "amount_over_limit",
                            rule.above_max,
                            f"{name} amount {amount:g} is above the limit {rule.max_amount:g}. A human must approve it.",
                            severity="high",
                            evidence=f"{rule.amount_field}={amount:g}",
                        )
                    )
        # strict profile: every side effect needs a human
        if ctx.scan.profile == "strict" and name in tg.side_effect_tools:
            out.append(
                self._finding(
                    "tool_governance",
                    "side_effect_requires_approval",
                    Action.REQUIRE_APPROVAL,
                    f"{name} has side effects and {principal.id} runs under the strict profile, so every such call "
                    "needs human approval.",
                    severity="medium",
                )
            )
        # lethal trifecta
        tri = tg.lethal_trifecta
        if tri.enabled and name in tg.side_effect_tools:
            s = self.store.session(ctx.session_id)
            if "untrusted" in s.taint and "sensitive" in s.taint and self._is_outbound(tg, name, args):
                untrusted = ", ".join(s.taint_sources.get("untrusted", [])[:3])
                sensitive = ", ".join(s.taint_sources.get("sensitive", [])[:3])
                out.append(
                    self._finding(
                        "tool_governance",
                        "lethal_trifecta",
                        tri.action,
                        f"{name} was stopped: this session read untrusted content ({untrusted}) and sensitive data "
                        f"({sensitive}), and this call sends data out. A human must approve this exact call.",
                        severity="critical",
                    )
                )
        return out

    @staticmethod
    def _is_outbound(tg: Any, name: str, args: Any) -> bool:
        rule = tg.arguments.get(name)
        if rule is None or rule.to_domains_allow is None or not isinstance(args, dict):
            return True
        for fld in rule.recipient_fields:
            for addr in _as_list(args.get(fld)):
                dom = addr.rsplit("@", 1)[-1].strip().lower() if "@" in addr else ""
                if dom and not any(dom == d or dom.endswith("." + d) for d in rule.to_domains_allow):
                    return True
        # recipients all internal: still outbound for payments/code; for mail it stays inside
        return not any(_as_list(args.get(f)) for f in rule.recipient_fields)

    async def _goal_alignment(self, ctx: RequestCtx, tg: Any, name: str, args: Any) -> list[Finding]:
        jc = ctx.doc.judge
        qs = {k: v.model_dump(exclude_none=True) for k, v in jc.questions.items() if k in ("goal_alignment", "exfiltration")}
        if not self._judge_enabled(ctx) or not qs:
            return []
        ctx.escalated = True
        untrusted = self._recent_untrusted(ctx)
        masked_args = self._masked_args(ctx, json.dumps(args, ensure_ascii=False) if not isinstance(args, str) else args)
        state = {
            "USER_REQUEST": _clip(self.audit_mask(ctx, ctx.user_request, "input"), 600),
            "PROPOSED_ACTION": _clip(f"{name}({json.dumps(masked_args, ensure_ascii=False)})", 1200),
        }
        if untrusted:
            state["UNTRUSTED_CONTENT"] = _clip(untrusted, 1200)
        res = await self._judge_call(ctx, state, qs, "side_effect_tool")
        if res is None:
            return []
        if res.get("error"):
            return [self._judge_failure(ctx, "tool_governance", res["error"], None)]
        out = []
        answers = res.get("answers") or {}
        mis = float((answers.get("goal_alignment") or {}).get("misaligned", 0.0))
        exf = float((answers.get("exfiltration") or {}).get("yes", 0.0))
        ga = tg.goal_alignment
        thr = ga.block_above
        if ga.approval_above is not None and ga.approval_above <= mis < thr:
            out.append(
                self._finding(
                    "tool_governance",
                    "goal_unclear",
                    Action.REQUIRE_APPROVAL,
                    f"T2 judge is not sure {name} serves the user's request (p(misaligned)={mis:.2f}, approval at "
                    f"{ga.approval_above}). A human must approve this exact call.",
                    tier="T2",
                    severity="medium",
                    score=mis,
                )
            )
        if mis >= thr:
            out.append(
                self._finding(
                    "tool_governance",
                    "goal_misaligned",
                    Action.BLOCK,
                    f"T2 judge rated {name} as not serving the user's request (p(misaligned)={mis:.2f} >= {thr}). "
                    "The agent may have been redirected by injected content.",
                    tier="T2",
                    severity="high",
                    score=mis,
                )
            )
        if exf >= ga.exfiltration_approval_above:
            out.append(
                self._finding(
                    "tool_governance",
                    "exfiltration",
                    Action.REQUIRE_APPROVAL,
                    f"T2 judge rated {name} as sending internal or personal data outside the organization "
                    f"(p={exf:.2f} >= {ga.exfiltration_approval_above}). A human must approve it.",
                    tier="T2",
                    severity="high",
                    score=exf,
                )
            )
        return out

    def _recent_untrusted(self, ctx: RequestCtx) -> str:
        body = ctx.scan.extra.get("body") or {}
        tg = ctx.doc.controls.tool_governance
        if not body or tg is None:
            return ""
        from bouncer.messages import extract_input_segments

        segs = extract_input_segments(body, self.known_tools(ctx), set(tg.untrusted_source_tools))
        texts = [s.text for s in segs if s.direction == "tool_result" and not s.trusted]
        return "\n---\n".join(texts[-2:])

    # ------------------------------------------------------------------ decisions and audit
    def _decision(self, ctx: RequestCtx, findings: list[Finding], action: Action, phase: str) -> Decision:
        if action < Action.REQUIRE_APPROVAL:
            return Decision(action=action, findings=findings)
        top = _top_finding(findings)
        status = 403
        if top is not None and top.control in ("budgets",) and top.rule in ("tokens_per_minute", "team_usd_per_day", "session_usd", "gpu_seconds_per_hour"):
            status = 429
        if top is not None and top.control == "loops" and top.rule == "circuit_breaker_open":
            status = 429
        approval_id = None
        if action == Action.REQUIRE_APPROVAL:
            approval_id = self._create_approval(ctx, findings, phase)
        msg = top.message if top else "Blocked by policy."
        if approval_id:
            msg = f"{msg} Approval id {approval_id}."
        ctx.approval_id = approval_id or ctx.approval_id
        ctx.status_code = status
        ctx.message = msg
        return Decision(action=action, findings=findings, status=status, code=top.id if top else None, message=msg, approval_id=approval_id)

    def _create_approval(self, ctx: RequestCtx, findings: list[Finding], phase: str) -> str | None:
        if not ctx.doc.approvals.enabled:
            return None
        appr_findings = [f for f in findings if f.effective_action == Action.REQUIRE_APPROVAL]
        call = None
        for rec in ctx.tool_calls:
            if any(fid in rec.get("findings", []) for fid in (f.id for f in appr_findings)):
                call = rec
                break
        if call is None:
            h = ctx.input_key or call_hash("input", ctx.excerpt)
            tool, args = "(prompt)", ctx.excerpt[:200]
        else:
            h, tool, args = call["call_hash"], call["tool"], json.dumps(call["arguments"], ensure_ascii=False)[:500]
        appr = self.store.create_approval(
            principal=ctx.principal.id,
            principal_key=principal_key(ctx.principal),
            team=ctx.principal.team,
            session_id=ctx.session_id,
            call_hash=h,
            tool=tool,
            arguments_masked=args,
            reason="; ".join(f.message for f in appr_findings)[:600],
            finding_ids=[f.id for f in appr_findings],
            trace_id=ctx.trace_id,
            ttl_seconds=ctx.doc.approvals.ttl_seconds,
        )
        return appr.id

    def output_decision(self, ctx: RequestCtx, findings: list[Finding]) -> Decision:
        action = self.finalize(ctx, findings)
        ctx.findings.extend(findings)
        return self._decision(ctx, findings, action, phase="output")

    def record_usage(self, ctx: RequestCtx, usage: dict[str, Any] | None, upstream_ms: float) -> dict[str, Any]:
        doc = ctx.doc
        usage = usage or {}
        pt = int(usage.get("prompt_tokens") or 0)
        ct = int(usage.get("completion_tokens") or 0)
        mcfg = doc.models.get(ctx.model or "")
        cost = 0.0
        gpu_s = 0.0
        if mcfg is not None:
            cost = pt * mcfg.price_per_1m_tokens.input / 1e6 + ct * mcfg.price_per_1m_tokens.output / 1e6
            up = doc.upstreams.get(mcfg.upstream)
            if up is not None and up.local:
                gpu_s = upstream_ms / 1000.0
                cost += gpu_s * mcfg.gpu_usd_per_second
        self.store.add_spend(ctx.principal.team, ctx.session_id, cost, pt + ct, gpu_s)
        self.store.session(ctx.session_id).steps += 1
        self.telemetry.spend.labels(ctx.principal.team, ctx.model or "").inc(cost)
        self.telemetry.tokens.labels(ctx.principal.team, "prompt").inc(pt)
        self.telemetry.tokens.labels(ctx.principal.team, "completion").inc(ct)
        tb = (doc.budgets.teams.get(ctx.principal.team) if doc.budgets else None)
        left = None
        if tb and tb.usd_per_day is not None:
            left = round(tb.usd_per_day - self.store.team_spend_today(ctx.principal.team), 6)
        return {
            "prompt_tokens": pt,
            "completion_tokens": ct,
            "cost_usd": round(cost, 8),
            "gpu_seconds": round(gpu_s, 3),
            "budget_left_usd": left,
            "estimated": bool(usage.get("estimated")),
        }

    def finish(
        self,
        ctx: RequestCtx,
        action: Action,
        usage: dict[str, Any] | None = None,
        direction: str | None = None,
        extra: dict[str, Any] | None = None,
        status_code: int | None = None,
        message: str | None = None,
    ) -> dict[str, Any]:
        total = _now_ms() - ctx.started_ms
        if status_code is None:
            status_code = ctx.status_code or (200 if action < Action.REQUIRE_APPROVAL else 403)
        if message is None:
            message = ctx.message
        lat = {k: round(v, 3) for k, v in ctx.latency.items()}
        lat["gateway_overhead"] = round(max(total - ctx.latency.get("upstream", 0.0), 0.0), 3)
        lat["total"] = round(total, 3)
        # strongest decision first, so the trace and exports lead with the rule that decided
        findings = sorted(
            ctx.findings,
            key=lambda f: (int(f.effective_action if f.effective_action is not None else f.action), SEVERITY_ORDER.get(f.severity, 0), f.score),
            reverse=True,
        )
        mcfg = ctx.doc.models.get(ctx.model or "")
        event = {
            "type": "decision",
            "trace_id": ctx.trace_id,
            "principal": ctx.principal.to_dict(),
            "session_id": ctx.session_id,
            "route": ctx.route,
            "direction": direction or ctx.direction,
            "model": ctx.model,
            "upstream": mcfg.upstream if mcfg else None,
            "action": action.label,
            "enforced": not any(f.monitor for f in findings) or action >= Action.REQUIRE_APPROVAL,
            "status_code": status_code,
            "tool": ctx.tool_calls[0]["tool"] if ctx.tool_calls else None,
            "message": message,
            "findings": [f.to_dict() for f in findings],
            "judge": ctx.judge or {"invoked": False},
            "t1": ctx.t1_scores,
            "tool_calls": [{k: v for k, v in tc.items()} for tc in ctx.tool_calls],
            "latency_ms": lat,
            "usage": usage or {},
            "policy": {"version": ctx.policy.version, "profile": ctx.scan.profile, "mode": ctx.doc.defaults.mode},
            "approval_id": ctx.approval_id,
            "downgraded_from": ctx.downgraded_from,
            "notes": ctx.notes,
            "excerpt": ctx.excerpt,
        }
        if extra:
            event.update(extra)
        for f in findings:
            self.telemetry.findings.labels(f.control, (f.effective_action or f.action).label).inc()
        self.telemetry.record_request(ctx.route, action.label, lat, ctx.escalated, ctx.t1_ran)
        return self.audit.write(event)


# ---------------------------------------------------------------------- utilities


def _enabled(cfg: Any) -> bool:
    return cfg is not None and getattr(cfg, "enabled", True)


def _digest(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _copy_finding(f: Finding) -> Finding:
    return Finding(
        control=f.control,
        rule=f.rule,
        tier=f.tier,
        severity=f.severity,
        action=f.action,
        score=f.score,
        message=f.message,
        span=f.span,
        evidence=f.evidence,
        owasp_llm=list(f.owasp_llm),
        owasp_agentic=list(f.owasp_agentic),
        atlas=list(f.atlas),
        signature_id=f.signature_id,
        view=f.view,
        direction=f.direction,
        source=f.source,
        location=f.location,
    )


def apply_redactions(text: str, findings: list[Finding]) -> str:
    spans = sorted({(f.span[0], f.span[1], f.rule) for f in findings if f.span}, key=lambda s: (s[0], -s[1]))
    if not spans:
        return text
    merged: list[list[Any]] = []
    for s, e, rule in spans:
        s, e = max(0, s), min(len(text), e)
        if s >= e:
            continue
        if merged and s < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
            continue
        merged.append([s, e, rule])
    out, pos = [], 0
    for s, e, rule in merged:
        out.append(text[pos:s])
        out.append(f"[REDACTED:{rule}]")
        pos = e
    out.append(text[pos:])
    return "".join(out)


def _top_finding(findings: list[Finding]) -> Finding | None:
    best = None
    for f in findings:
        eff = f.effective_action if f.effective_action is not None else f.action
        key = (eff, SEVERITY_ORDER.get(f.severity, 0), f.score)
        if best is None or key > best[0]:
            best = (key, f)
    return best[1] if best else None


def _safe_excerpt(body: dict[str, Any], cleaned: list[tuple[Segment, str, list[Finding]]], n: int) -> str:
    """Audit excerpt with every secret and PII value masked, whatever the action was (a blocked secret is not
    redacted in the request, but it must never reach the audit log). A segment where a secret was found only
    in a normalized or decoded form (no exact position) is withheld entirely."""
    import copy

    shadow = copy.deepcopy(body)
    for seg, clean, segf in cleaned:
        if seg.direction == "tool_definition":
            continue
        sensitive = [f for f in segf if f.control in REDACTION_CONTROLS]
        if any(f.span is None for f in sensitive):
            text = f"[withheld: {', '.join(sorted({f.id for f in sensitive if f.span is None}))} found in an encoded or normalized form]"
        else:
            text = apply_redactions(clean, sensitive)
        try:
            set_in(shadow, seg.location, text)
        except (KeyError, IndexError, TypeError):
            continue
    return _excerpt(shadow, n)


def _excerpt(body: dict[str, Any], n: int) -> str:
    msgs = body.get("messages") or []
    for m in reversed(msgs):
        if isinstance(m, dict) and m.get("role") in ("user", "tool") and isinstance(m.get("content"), str):
            return m["content"][:n]
    return ""


def principal_key(principal: Principal) -> str:
    return f"{principal.via}>{principal.id}" if principal.via else principal.id


def describe_source(source: str) -> str:
    """Human wording for a segment source in block messages."""
    role, _, tool = source.partition(":")
    return {
        "user": "the user message",
        "system": "the system prompt",
        "assistant": "the model output",
        "tool_result": f"the result of {tool}",
        "tool_definition": f"the definition of tool {tool}",
        "tool_call": f"the arguments of {tool}",
        "memory_write": f"the content {tool} would save to shared memory",
    }.get(role, source)


def _clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 20] + " ...[truncated]"


def _windows(text: str, size: int, overlap: int, max_windows: int) -> list[str]:
    """Overlapping windows that cover the text; above max_windows, evenly spaced ones incl. first and last."""
    if len(text) <= size:
        return [text]
    step = size - overlap
    starts = list(range(0, max(len(text) - overlap, 1), step))
    if starts[-1] + size < len(text):
        starts.append(len(text) - size)
    if len(starts) > max_windows:
        idx = [round(i * (len(starts) - 1) / (max_windows - 1)) for i in range(max_windows)]
        starts = [starts[i] for i in sorted(set(idx))]
    return [text[a : a + size] for a in starts]


def _as_list(v: Any) -> list[str]:
    if v is None or v == "":
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [s.strip() for s in str(v).replace(";", ",").split(",") if s.strip()]


def _to_float(v: Any) -> float | None:
    try:
        return float(str(v).replace(",", "").replace(" ", ""))
    except (TypeError, ValueError):
        return None


def _mask_args(args: Any) -> Any:
    """Arguments for the audit trail: long values truncated (secrets inside are already redacted)."""
    if isinstance(args, dict):
        return {k: _mask_args(v) for k, v in args.items()}
    if isinstance(args, list):
        return [_mask_args(v) for v in args[:20]]
    if isinstance(args, str) and len(args) > 300:
        return args[:300] + "...[truncated]"
    return args


def _judge_result_dict(res: Any) -> dict[str, Any]:
    if isinstance(res, dict):
        d = dict(res)
    else:
        d = {k: getattr(res, k) for k in ("invoked", "reason", "backend", "answers", "latency_ms", "cached", "error") if hasattr(res, k)}
    d.setdefault("invoked", True)
    return d


def _load_normalizer():  # noqa: ANN202
    try:
        from bouncer.controls.normalize import prepare

        return prepare
    except Exception:  # module not available yet: identity normalization
        log.warning("bouncer.controls.normalize unavailable; using identity normalization")

        def prepare(segment: Segment, cfg: Any):  # noqa: ANN202
            return segment.text, [View(segment.text, "raw")], []

        return prepare
