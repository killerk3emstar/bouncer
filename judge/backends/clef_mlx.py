"""Clef-Flash (Cloudflare, Apache-2.0) on Apple Silicon through MLX.

One prefill pass over [system, STATE, SCHEMA] scores every option of every question; there is
no text generation, so the answer always fits the schema.

Hardening applied before the model sees the state:
- Chat-template control tokens inside the state (``<|im_end|>``, ``<|im_start|>``, ``<think>`` ...)
  are broken up ("< |im_end|>"). Without this the tokenizer turns attacker text into real control
  tokens and the untrusted content can close the user turn and forge its own schema answers.
- When the state is longer than the token budget, the longest field (normally UNTRUSTED_CONTENT)
  is cut in the middle, keeping its head and tail, instead of dropping the end of the rendered
  JSON (which would silently drop USER_REQUEST, the last key in sorted order).
"""

from __future__ import annotations

import json
import os
import re
import time
from functools import lru_cache
from typing import Any

from judge.backends.base import Backend, BackendError, Decision, finalize, output_keys

DEFAULT_PATH = "models/clef-flash-mlx-4bit"
_FALLBACK_SPECIAL = re.compile(r"<\|[A-Za-z0-9_]{1,40}\|>|</?(think|tool_call|tool_response)>|<tts_[a-z_]{1,30}>")


def to_clef_question(q: dict[str, Any]) -> dict[str, Any]:
    """Our normalized question -> Clef question. Score questions with named criteria become a list."""
    qtype = q["type"]
    out: dict[str, Any] = {"type": qtype, "instructions": q.get("instructions")}
    criteria = q.get("criteria")
    if qtype == "noul":
        if criteria:
            mapped = {{"yes": "true", "no": "false"}.get(k, k): v for k, v in criteria.items()}
            out["criteria"] = mapped
    elif qtype == "score" and isinstance(criteria, dict):
        out["criteria"] = [f"{name}: {desc}" for name, desc in criteria.items()]
    else:
        out["criteria"] = criteria
    return out


def from_clef_answer(q: dict[str, Any], probs: dict[str, float]) -> dict[str, float]:
    """Clef option ids -> our answer keys (yes/no, criteria names, list indices)."""
    if q["type"] == "noul":
        return {"yes": probs.get("true", 0.0), "no": probs.get("false", 0.0)}
    keys = output_keys(q)
    if q["type"] == "score":
        return {k: probs.get(str(i), 0.0) for i, k in enumerate(keys)}
    return {k: probs.get(k, 0.0) for k in keys}


def _cut_middle(text: str, drop_chars: int) -> str:
    """Drop ``drop_chars`` characters from the middle of ``text``, keeping at least 200."""
    drop_chars = min(drop_chars, max(0, len(text) - 200))
    if drop_chars <= 0:
        return text
    keep = len(text) - drop_chars
    head = keep * 2 // 3
    tail = keep - head
    return f"{text[:head]}\n[... {drop_chars} characters omitted by the judge ...]\n{text[len(text) - tail:]}"


class ClefMLXBackend(Backend):
    name = "clef-mlx"

    def __init__(self, path: str = DEFAULT_PATH, max_tokens: int = 1536) -> None:
        super().__init__()
        self.path = path
        self.model = os.path.basename(os.path.normpath(path)) or "clef-flash-mlx"
        self.max_tokens = max_tokens
        self._clef = None
        self._special_re: re.Pattern[str] = _FALLBACK_SPECIAL
        self.load_ms: float | None = None

    # ------------------------------------------------------------------ lifecycle
    def load(self) -> None:
        index = os.path.join(self.path, "model.safetensors.index.json")
        head = os.path.join(self.path, "joint_head.safetensors")
        if not (os.path.isfile(index) and os.path.isfile(head)):
            raise BackendError(f"Clef checkpoint not found or incomplete at {self.path!r} (run `make models`)")
        try:
            import mlx.core  # noqa: F401
        except ImportError as exc:  # Linux containers: use ollama-guard instead
            raise BackendError("mlx is not installed; the clef-mlx backend needs Apple Silicon") from exc
        from judge.backends import clef_port

        t0 = time.perf_counter()
        self._clef = clef_port.load(self.path)
        self.load_ms = (time.perf_counter() - t0) * 1000
        self._special_re = self._build_special_re(self._clef[1])
        self.loaded = True

    @staticmethod
    def _build_special_re(tok) -> re.Pattern[str]:
        try:
            added = list(tok.get_added_vocab().keys())
        except Exception:  # noqa: BLE001 - tokenizer wrappers differ between mlx-lm versions
            return _FALLBACK_SPECIAL
        added = [t for t in added if len(t) >= 3 and not t.isalnum()]
        if not added:
            return _FALLBACK_SPECIAL
        alt = "|".join(re.escape(t) for t in sorted(added, key=len, reverse=True))
        return re.compile(f"{alt}|{_FALLBACK_SPECIAL.pattern}")

    def info(self) -> dict[str, Any]:
        out: dict[str, Any] = {"path": self.path, "max_tokens": self.max_tokens, "load_ms": self.load_ms}
        try:
            import mlx.core as mx

            get_peak = getattr(mx, "get_peak_memory", None) or mx.metal.get_peak_memory
            get_active = getattr(mx, "get_active_memory", None) or mx.metal.get_active_memory
            out["peak_memory_mb"] = round(get_peak() / 2**20, 1)
            out["active_memory_mb"] = round(get_active() / 2**20, 1)
        except Exception:  # noqa: BLE001
            pass
        return out

    # ------------------------------------------------------------------ helpers
    def sanitize(self, value: Any) -> Any:
        """Break up chat-template control tokens in every string of the state."""
        if isinstance(value, str):
            return self._special_re.sub(lambda m: m.group(0)[0] + " " + m.group(0)[1:], value)
        if isinstance(value, dict):
            return {k: self.sanitize(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.sanitize(v) for v in value]
        return value

    def _tokens(self, text: str) -> list[int]:
        return self._clef[1].encode(text, add_special_tokens=False)

    @lru_cache(maxsize=64)  # noqa: B019 - one backend instance per process
    def _schema(self, questions_json: str):
        from judge.backends import clef_port

        questions = json.loads(questions_json)
        schema, qs = clef_port.encode_schema(self._clef[1], questions)
        prefix, suffix = clef_port.frame(self._clef[1])
        return prefix, schema, suffix, qs

    def fit_state(self, state: Any, budget: int) -> tuple[Any, list[int], int]:
        """Return (state, state token ids, tokens dropped). Cuts the longest field in the middle."""
        from judge.backends.clef_port import render

        ids = self._tokens(render(state))
        original = len(ids)
        for _ in range(4):
            if len(ids) <= budget:
                return state, ids, original - len(ids)
            excess = len(ids) - budget
            rendered_len = len(render(state))
            chars_per_token = max(1.0, rendered_len / max(1, len(ids)))
            drop = int(excess * chars_per_token * 1.15) + 64
            if isinstance(state, dict):
                strings = {k: v for k, v in state.items() if isinstance(v, str)}
                if not strings:
                    break
                key = "UNTRUSTED_CONTENT" if len(strings.get("UNTRUSTED_CONTENT", "")) > drop else max(strings, key=lambda k: len(strings[k]))
                state = {**state, key: _cut_middle(state[key], drop)}
            elif isinstance(state, str):
                state = _cut_middle(state, drop)
            else:
                break
            ids = self._tokens(render(state))
        ids = ids[:budget]
        return state, ids, original - len(ids)

    # ------------------------------------------------------------------ decide
    def decide(self, state: Any, questions: dict[str, dict[str, Any]]) -> Decision:
        if self._clef is None:
            raise BackendError("model not loaded")
        import mlx.core as mx
        import numpy as np

        model, _tok, head, lex = self._clef
        clef_questions = {qid: to_clef_question(q) for qid, q in questions.items()}
        prefix, schema, suffix, qs_template = self._schema(json.dumps(clef_questions, sort_keys=False))
        budget = max(64, self.max_tokens - len(prefix) - len(schema) - len(suffix))
        state = self.sanitize(state)
        state, state_ids, dropped = self.fit_state(state, budget)
        off = len(prefix) + len(state_ids)
        qs = [
            {**q, "qspan": (q["qspan"][0] + off, q["qspan"][1] + off), "ospans": [(a + off, b + off) for a, b in q["ospans"]]}
            for q in qs_template
        ]
        ids = prefix + state_ids + schema + suffix
        t0 = time.perf_counter()
        hidden = model.language_model.model(mx.array(ids)[None])[0]
        mx.eval(hidden)
        t1 = time.perf_counter()
        logits = head(hidden, ids, qs, lex)
        raw = {}
        for qid, q, lg in zip(clef_questions, qs, logits, strict=True):
            raw[qid] = dict(zip(q["oids"], np.array(mx.softmax(lg)).tolist(), strict=True))
        t2 = time.perf_counter()
        answers = {qid: from_clef_answer(questions[qid], raw[qid]) for qid in questions}
        return Decision(
            answers=finalize(answers, questions),
            input_tokens=len(ids),
            truncated=dropped > 0,
            meta={"prefill_ms": round((t1 - t0) * 1000, 1), "head_ms": round((t2 - t1) * 1000, 1),
                  "dropped_tokens": dropped},
        )
