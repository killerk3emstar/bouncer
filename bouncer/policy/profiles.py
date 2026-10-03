"""Strictness profiles.

The values in policy/bouncer.yaml are the `balanced` baseline. A profile is a transform applied on
top of the file, globally (`profile:`) or per principal (`principals.<id>.profile`):

  strict      lowers injection thresholds, turns `log` PII into `redact`, requires approval for every
              side-effect tool call, fails closed.
  permissive  records non-critical findings as `log` instead of enforcing them (shadow rollout),
              keeps blocking critical ones, fails open.
  balanced    the file as written.
"""

from __future__ import annotations

from bouncer.policy.schema import PolicyDoc

PROFILE_NOTES = {
    "balanced": "Policy file as written.",
    "strict": (
        "Injection thresholds capped (T1 block 0.90, escalate 0.30; T2 block 0.70, approval 0.45), "
        "PII marked log becomes redact, every side-effect tool call needs approval, fail closed."
    ),
    "permissive": "Non-critical findings are recorded as log instead of enforced; critical ones still block; fail open.",
}

STRICT_CAPS = {
    "classifier.block_above": 0.90,
    "classifier.escalate_above": 0.30,
    "judge.block_above": 0.70,
    "judge.approval_above": 0.45,
}


def apply_profile(doc: PolicyDoc, profile: str) -> PolicyDoc:
    """Return a transformed deep copy of the policy for the given profile."""
    if profile == "balanced":
        return doc
    out = doc.model_copy(deep=True)
    if profile == "strict":
        out.defaults.fail_mode = "closed"
        pi = out.controls.prompt_injection
        if pi is not None:
            pi.classifier.block_above = min(pi.classifier.block_above, STRICT_CAPS["classifier.block_above"])
            pi.classifier.escalate_above = min(
                pi.classifier.escalate_above, STRICT_CAPS["classifier.escalate_above"]
            )
            pi.judge.block_above = min(pi.judge.block_above, STRICT_CAPS["judge.block_above"])
            pi.judge.approval_above = min(pi.judge.approval_above, STRICT_CAPS["judge.approval_above"])
        pii = out.controls.pii
        if pii is not None:
            pii.entities = {k: ("redact" if v in ("allow", "log") else v) for k, v in pii.entities.items()}
    elif profile == "permissive":
        out.defaults.fail_mode = "open"
    return out
