"""Deterministic stand-in for the T1 model, used by `make test` (no model files, no network).

Score lookup order for each text:
1. `overrides` passed to the constructor (exact text -> score), for tests that need a given score.
2. Recorded real-model scores in tests/fixtures/t1_scores.json, keyed by sha256 of the exact
   UTF-8 text. Produce them with `uv run python scripts/record_t1.py` (needs the ONNX model).
3. A transparent keyword heuristic (HEURISTIC_RULES below), so new test cases written without the
   model still get a sensible score. Like the real model, it only knows English phrasings.
   score = 1 - (1 - BASE_SCORE) * prod(1 - weight) over the rules that match.

Texts that miss the fixture can be appended to a file for later recording: set env
T1_FAKE_MISSES=path/to/misses.jsonl, run the tests, then
`uv run python scripts/record_t1.py --from-dump path/to/misses.jsonl`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from pathlib import Path

from bouncer.t1.classifier import REPO_ROOT

DEFAULT_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "t1_scores.json"
BASE_SCORE = 0.01

# (rule id, pattern, weight). Weights are rough: 0.9+ means "the real model almost always fires".
HEURISTIC_RULES: list[tuple[str, re.Pattern[str], float]] = [
    (
        "override-previous",
        re.compile(
            r"\b(ignore|disregard|forget|skip|override|bypass)\b[^.\n]{0,40}?"
            r"\b(previous|prior|above|earlier|preceding|all|any|your|the|these)\b[^.\n]{0,30}?"
            r"\b(instructions?|prompts?|rules?|directives?|guidelines?|messages?|context|tasks?)\b",
            re.IGNORECASE,
        ),
        0.97,
    ),
    (
        "prompt-leak",
        re.compile(
            r"\b(reveal|print|show|repeat|output|display|dump|tell me|spell[- ]check)\b[^.\n]{0,40}?"
            r"\b(system prompt|your instructions|everything above|text above|initial prompt|hidden prompt|"
            r"prompt texts?|above prompt|your prompt)\b",
            re.IGNORECASE,
        ),
        0.9,
    ),
    (
        "new-instructions",
        re.compile(r"\b(new|updated|real|actual|hidden|secret)\s+(instructions?|task|directive|system prompt)\b", re.I),
        0.6,
    ),
    (
        "role-reassign",
        re.compile(r"\byou are (now|no longer)\b|\bfrom now on\b|\bact as an? (unrestricted|unfiltered|jailbroken)\b", re.I),
        0.7,
    ),
    (
        "mode-switch",
        re.compile(r"\b(developer|god|dan|jailbreak|unrestricted)\s+mode\b|\bDAN\b|\bdo anything now\b", re.I),
        0.85,
    ),
    (
        "chat-template",
        re.compile(r"<\|im_start\|>|<\|im_end\|>|\[/?INST\]|<\|system\|>|<\|endoftext\|>|<<SYS>>", re.I),
        0.9,
    ),
    (
        "fake-system",
        re.compile(r"(^|\n)\s*(#{1,6}\s*|\[|<)?(system|admin)\s*(:|\]|>|message|override|note)", re.I),
        0.5,
    ),
    (
        "exfil-instruction",
        re.compile(
            r"\b(send|forward|email|e-mail|upload|post|exfiltrate)\b[^\n]{0,80}?\b(to|at)\b[^\n]{0,40}?"
            r"[\w.+-]+@[\w-]+\.[\w.]+",
            re.I,
        ),
        0.75,
    ),
    (
        "hide-from-user",
        re.compile(r"\b(do not|don't|never)\s+(tell|inform|mention|notify|alert)\s+(this to\s+)?(the\s+)?user\b", re.I),
        0.8,
    ),
]


def text_key(text: str) -> str:
    """Fixture key: sha256 of the exact UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def heuristic_score(text: str) -> tuple[float, list[str]]:
    """Return (score, matched rule ids). Pure function, documented in the module docstring."""
    if not text or not text.strip():
        return 0.0, []
    keep = 1.0 - BASE_SCORE
    matched = []
    for rule_id, pattern, weight in HEURISTIC_RULES:
        if pattern.search(text):
            matched.append(rule_id)
            keep *= 1.0 - weight
    return round(1.0 - keep, 6), matched


def load_fixture(path: str | os.PathLike[str] | None = None) -> dict[str, float]:
    """Read {sha256: score} from the fixture file. Missing file = empty dict."""
    p = Path(path) if path else DEFAULT_FIXTURE
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    out: dict[str, float] = {}
    for key, value in data.get("scores", {}).items():
        out[key] = float(value["score"] if isinstance(value, dict) else value)
    return out


class FakeInjectionClassifier:
    """Offline T1 for tests: overrides -> recorded real scores -> keyword heuristic."""

    name = "fake-t1"

    def __init__(
        self,
        overrides: dict[str, float] | None = None,
        *,
        fixture_path: str | os.PathLike[str] | None = None,
        use_fixture: bool = True,
        use_heuristic: bool = True,
        default: float = BASE_SCORE,
        misses_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self.overrides = dict(overrides or {})
        self.fixture_path = fixture_path
        self.use_fixture = use_fixture
        self.use_heuristic = use_heuristic
        self.default = default
        self.misses_path = misses_path or os.environ.get("T1_FAKE_MISSES") or None
        self._fixture: dict[str, float] | None = None
        self._lock = threading.Lock()
        self.calls: list[list[str]] = []  # every score() input, for assertions in tests
        self.sources: dict[str, str] = {}  # text -> "override" | "fixture" | "heuristic" | "default"

    def _fixture_scores(self) -> dict[str, float]:
        if self._fixture is None:
            with self._lock:
                if self._fixture is None:
                    self._fixture = load_fixture(self.fixture_path) if self.use_fixture else {}
        return self._fixture

    def score_one(self, text: str) -> float:
        if text in self.overrides:
            self.sources[text] = "override"
            return float(self.overrides[text])
        recorded = self._fixture_scores().get(text_key(text))
        if recorded is not None:
            self.sources[text] = "fixture"
            return recorded
        self._record_miss(text)
        if self.use_heuristic:
            self.sources[text] = "heuristic"
            return heuristic_score(text)[0]
        self.sources[text] = "default"
        return self.default

    def score(self, texts: list[str]) -> list[float]:
        self.calls.append(list(texts))
        return [self.score_one(t) for t in texts]

    def _record_miss(self, text: str) -> None:
        if not self.misses_path or not text.strip():
            return
        with self._lock, open(self.misses_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"text": text}, ensure_ascii=False) + "\n")
