"""Backend interface and the question / answer normalization shared by every backend.

Question schema (the "System One" shape used by Clef, Jev and basal):

    {"injection": {"type": "noul", "instructions": "..."},
     "goal_alignment": {"type": "score", "instructions": "...",
                        "criteria": {"aligned": "...", "unclear": "...", "misaligned": "..."}},
     "harm": {"type": "choice", "instructions": "...", "criteria": {"none": "...", "fraud": "..."}}}

Answer keys after normalization (identical for every backend):

    noul                  -> "yes", "no"
    score, dict criteria  -> the criteria names, in the order given
    score, list criteria  -> "0", "1", ... (index of the criterion)
    choice                -> the criteria keys, in the order given

Probabilities sum to 1 for every question.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

QUESTION_TYPES = ("noul", "score", "choice")
MAX_QUESTIONS = 16
MAX_OPTIONS = 32
STATE_KEYS = ("USER_REQUEST", "UNTRUSTED_CONTENT", "PROPOSED_ACTION")


class QuestionError(ValueError):
    """The question schema is invalid (unknown type, missing or malformed criteria)."""


class BackendError(RuntimeError):
    """The backend could not produce an answer (model failure, upstream error)."""


@dataclass
class Decision:
    """What a backend returns for one state."""

    answers: dict[str, dict[str, float]]
    input_tokens: int | None = None
    truncated: bool = False
    meta: dict[str, Any] = field(default_factory=dict)


def normalize_questions(questions: Any) -> dict[str, dict[str, Any]]:
    """Validate a question schema and return a clean copy (insertion order kept).

    Raises QuestionError with a message that names the offending question.
    """
    if not isinstance(questions, dict) or not questions:
        raise QuestionError("questions must be a non-empty object keyed by question id")
    if len(questions) > MAX_QUESTIONS:
        raise QuestionError(f"at most {MAX_QUESTIONS} questions per request, got {len(questions)}")
    clean: dict[str, dict[str, Any]] = {}
    for qid, q in questions.items():
        if not isinstance(qid, str) or not qid:
            raise QuestionError("question ids must be non-empty strings")
        if not isinstance(q, dict):
            raise QuestionError(f"question '{qid}' must be an object")
        qtype = q.get("type")
        if qtype not in QUESTION_TYPES:
            raise QuestionError(f"question '{qid}': type must be one of {', '.join(QUESTION_TYPES)}, got {qtype!r}")
        instructions = q.get("instructions")
        if instructions is not None and not isinstance(instructions, str):
            raise QuestionError(f"question '{qid}': instructions must be a string")
        criteria = q.get("criteria")
        if qtype == "noul":
            if criteria is not None:
                if not isinstance(criteria, dict) or not set(criteria) <= {"yes", "no", "true", "false"}:
                    raise QuestionError(
                        f"question '{qid}': noul criteria may only describe the options yes/no (or true/false)"
                    )
        elif qtype == "score":
            if isinstance(criteria, list):
                if len(criteria) < 2 or not all(isinstance(c, str) for c in criteria):
                    raise QuestionError(f"question '{qid}': score criteria list needs at least 2 strings")
            elif isinstance(criteria, dict):
                _check_named_criteria(qid, criteria)
            else:
                raise QuestionError(f"question '{qid}': score questions need criteria (a list or an object)")
        else:  # choice
            if not isinstance(criteria, dict):
                raise QuestionError(f"question '{qid}': choice questions need criteria as an object")
            _check_named_criteria(qid, criteria)
        entry: dict[str, Any] = {"type": qtype}
        if instructions is not None:
            entry["instructions"] = instructions
        if criteria is not None:
            entry["criteria"] = list(criteria) if isinstance(criteria, list) else dict(criteria)
        clean[qid] = entry
    return clean


def _check_named_criteria(qid: str, criteria: dict) -> None:
    if len(criteria) < 2:
        raise QuestionError(f"question '{qid}': needs at least 2 criteria")
    if len(criteria) > MAX_OPTIONS:
        raise QuestionError(f"question '{qid}': at most {MAX_OPTIONS} criteria")
    for k, v in criteria.items():
        if not isinstance(k, str) or not k:
            raise QuestionError(f"question '{qid}': criteria names must be non-empty strings")
        if not isinstance(v, str):
            raise QuestionError(f"question '{qid}': criterion '{k}' must have a string description")


def output_keys(question: dict[str, Any]) -> list[str]:
    """Answer keys for one (normalized) question, in their canonical order."""
    qtype = question["type"]
    if qtype == "noul":
        return ["yes", "no"]
    criteria = question["criteria"]
    if isinstance(criteria, list):
        return [str(i) for i in range(len(criteria))]
    return list(criteria)


def finalize(answers: dict[str, dict[str, float]], questions: dict[str, dict[str, Any]]) -> dict[str, dict[str, float]]:
    """Order keys canonically, fill missing options with 0, clip and renormalize to sum 1.

    A question missing from ``answers`` gets a uniform distribution.
    """
    out: dict[str, dict[str, float]] = {}
    for qid, q in questions.items():
        keys = output_keys(q)
        raw = answers.get(qid) or {}
        vals = []
        for k in keys:
            v = raw.get(k, 0.0)
            try:
                v = float(v)
            except (TypeError, ValueError):
                v = 0.0
            if not math.isfinite(v) or v < 0:
                v = 0.0
            vals.append(v)
        total = sum(vals)
        if total <= 0:
            vals = [1.0 / len(keys)] * len(keys)
        else:
            vals = [v / total for v in vals]
        rounded = [round(v, 6) for v in vals]
        top = max(range(len(rounded)), key=rounded.__getitem__)
        rounded[top] = round(1.0 - sum(r for i, r in enumerate(rounded) if i != top), 6)
        out[qid] = dict(zip(keys, rounded, strict=True))
    return out


def state_fields(state: Any) -> dict[str, str]:
    """Split a state into the three text fields the heuristic backends look at.

    A plain-text state is treated as UNTRUSTED_CONTENT. Non-string values are rendered as JSON.
    Unknown keys are appended to UNTRUSTED_CONTENT so that nothing is silently ignored.
    """
    import json

    def text(v: Any) -> str:
        if v is None:
            return ""
        return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, sort_keys=True)

    if isinstance(state, str):
        return {"USER_REQUEST": "", "UNTRUSTED_CONTENT": state, "PROPOSED_ACTION": ""}
    if not isinstance(state, dict):
        return {"USER_REQUEST": "", "UNTRUSTED_CONTENT": text(state), "PROPOSED_ACTION": ""}
    fields = {k: text(state.get(k)) for k in STATE_KEYS}
    extra = [f"{k}: {text(v)}" for k, v in state.items() if k not in STATE_KEYS]
    if extra:
        fields["UNTRUSTED_CONTENT"] = "\n".join([fields["UNTRUSTED_CONTENT"], *extra]).strip()
    return fields


class Backend:
    """Base class. Subclasses implement ``load`` and ``decide``; both are blocking and are
    called from one dedicated worker thread by the server (never concurrently)."""

    name: str = "base"
    model: str = ""

    def __init__(self) -> None:
        self.loaded = False

    def load(self) -> None:  # pragma: no cover - trivial default
        self.loaded = True

    def decide(self, state: Any, questions: dict[str, dict[str, Any]]) -> Decision:
        raise NotImplementedError

    async def adecide(self, state: Any, questions: dict[str, dict[str, Any]]) -> Decision:
        """Async entry point used for in-process calls (fake backend inside the gateway)."""
        return self.decide(state, questions)

    def info(self) -> dict[str, Any]:
        return {}
