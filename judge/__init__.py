"""Bouncer T2 semantic judge.

The judge answers a small set of typed questions about a redacted agent state
(USER_REQUEST, UNTRUSTED_CONTENT, PROPOSED_ACTION) with a probability for every
allowed option. It never generates free text, so its output always fits the schema
and policy thresholds apply directly to the probabilities.

Service: ``uv run python -m judge.server`` (POST /v1/decide, GET /health on :8701).
Client used by the gateway: :class:`judge.client.JudgeClient`.
"""

from judge.backends.base import QuestionError, normalize_questions, output_keys

__all__ = ["QuestionError", "normalize_questions", "output_keys"]
