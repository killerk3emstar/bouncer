"""T1: prompt-injection classifier on untrusted text fragments.

Model: protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0), ONNX export, run on CPU with
onnxruntime and the Rust `tokenizers` library (no torch, no transformers at runtime).

Known limits (from the model card, confirmed by our eval, see reports/t1.md):
- English only. Non-English text must be routed to T2 (see bouncer.t1.lang).
- Not trained to detect jailbreaks (DAN, role-play); those are for signatures and T2.
- False positives on system prompts: do not scan the operator's own system prompt with it.

Long texts are split into overlapping windows of at most 512 tokens ([CLS] + 510 + [SEP]). The
score of a text is the maximum over its windows, so an injection hidden in the middle of a long
web page is not diluted by benign text around it. All windows of all texts in one call are
batched together, sorted by length to keep padding small.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = "models/deberta-pi-v2/onnx"
MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"


@runtime_checkable
class InjectionClassifier(Protocol):
    """What the pipeline needs from T1. Implementations: OnnxInjectionClassifier, FakeInjectionClassifier."""

    name: str

    def score(self, texts: list[str]) -> list[float]:
        """Probability of prompt injection in [0, 1] for each text, same order as the input."""
        ...


@dataclass(frozen=True)
class T1Result:
    """Detailed result for one text.

    score: max injection probability over windows (0.0 for empty text).
    windows: number of windows the text was split into.
    windows_scored: windows actually scored (smaller than `windows` only if max_windows_per_text
        capped a very long text; then evenly spaced windows incl. first and last are scored and the
        rest of the text is NOT scanned: the pipeline should treat that as partial coverage, e.g.
        escalate to T2). Default cap 16 windows, about 7,000 tokens; one 512-token window costs
        roughly 150-230 ms on 4 CPU threads (reports/t1.md).
    span: character range [start, end) of the highest-scoring window in the input text, usable as
        the finding span in the audit trace. None for empty text.
    """

    score: float
    windows: int
    windows_scored: int
    span: tuple[int, int] | None


# ---------------------------------------------------------------------------------------------
# Pure helpers (unit-tested without the model)
# ---------------------------------------------------------------------------------------------


def plan_windows(
    n_tokens: int, window: int, overlap: int, max_windows: int | None = None
) -> tuple[list[tuple[int, int]], int]:
    """Cover token positions [0, n_tokens) with windows of at most `window` tokens.

    Consecutive windows overlap by `overlap` tokens so a phrase cut at a boundary appears whole in
    the next window. The last window is aligned to the end of the text. Returns (ranges, total)
    where total is the number of windows before any max_windows cap.
    """
    if window <= 0:
        raise ValueError("window must be positive")
    if not 0 <= overlap < window:
        raise ValueError("overlap must be in [0, window)")
    if n_tokens <= window:
        return [(0, n_tokens)], 1
    stride = window - overlap
    starts = list(range(0, n_tokens - window + 1, stride))
    if starts[-1] + window < n_tokens:
        starts.append(n_tokens - window)
    total = len(starts)
    if max_windows is not None and total > max_windows:
        if max_windows == 1:
            starts = [starts[0]]
        else:
            step = (total - 1) / (max_windows - 1)
            starts = [starts[round(i * step)] for i in range(max_windows)]
    return [(s, s + window) for s in starts], total


def make_batches(lengths: Sequence[int], max_batch: int, max_batch_tokens: int) -> list[list[int]]:
    """Group item indices into batches, sorted by length, bounded by count and padded token volume."""
    order = sorted(range(len(lengths)), key=lambda i: lengths[i])
    batches: list[list[int]] = []
    current: list[int] = []
    current_max = 0
    for i in order:
        new_max = max(current_max, lengths[i])
        if current and (len(current) + 1 > max_batch or new_max * (len(current) + 1) > max_batch_tokens):
            batches.append(current)
            current, new_max = [], lengths[i]
        current.append(i)
        current_max = new_max
    if current:
        batches.append(current)
    return batches


def softmax_injection(logits: np.ndarray, injection_index: int) -> np.ndarray:
    """Numerically stable softmax over the last axis, returning the injection-class column."""
    z = logits - logits.max(axis=-1, keepdims=True)
    e = np.exp(z)
    return (e / e.sum(axis=-1, keepdims=True))[:, injection_index]


def resolve_model_path(path: str | os.PathLike[str] | None = None) -> Path:
    """Explicit path, else env T1_MODEL_PATH, else the default; relative paths try cwd then repo root."""
    raw = Path(path or os.environ.get("T1_MODEL_PATH") or DEFAULT_MODEL_PATH)
    if raw.is_absolute() or raw.exists():
        return raw
    return REPO_ROOT / raw


# ---------------------------------------------------------------------------------------------
# ONNX implementation
# ---------------------------------------------------------------------------------------------


class OnnxInjectionClassifier:
    """protectai DeBERTa-v3 prompt-injection classifier on onnxruntime CPU.

    Lazy: the model loads on the first `score` call or on an explicit `load()` (call it at gateway
    start-up so the first request does not pay ~1 s of load + warm-up). Thread-safe: loading is
    guarded by a lock and inference calls are serialized, so concurrent requests do not
    oversubscribe the CPU (each call already uses `threads` intra-op threads). The gateway should
    call `score` from a worker thread (`await asyncio.to_thread(clf.score, texts)`).

    `session` and `tokenizer` can be injected (tests use a stub session).
    """

    name = "protectai-deberta-v3-pi-v2-onnx"

    def __init__(
        self,
        model_path: str | os.PathLike[str] | None = None,
        *,
        threads: int = 4,
        max_tokens: int = 512,
        overlap_tokens: int = 64,
        max_windows_per_text: int | None = 16,
        max_batch: int = 16,
        max_batch_tokens: int = 8192,
        warmup: bool = True,
        session: Any = None,
        tokenizer: Any = None,
        injection_index: int | None = None,
    ) -> None:
        self.model_path = resolve_model_path(model_path)
        self.threads = threads
        self.max_tokens = max_tokens
        self.window = max_tokens - 2  # room for [CLS] and [SEP]
        self.overlap = overlap_tokens
        self.max_windows_per_text = max_windows_per_text
        self.max_batch = max_batch
        self.max_batch_tokens = max_batch_tokens
        self.warmup = warmup
        self._session = session
        self._tokenizer = tokenizer
        self._injection_index = injection_index
        self._load_lock = threading.Lock()
        self._infer_lock = threading.Lock()
        self._loaded = session is not None and tokenizer is not None
        self.load_seconds: float | None = None
        if self._loaded:
            self._init_special_ids()

    # -- loading -------------------------------------------------------------------------------

    def load(self) -> OnnxInjectionClassifier:
        """Load model and tokenizer once and run a warm-up inference. Safe to call repeatedly."""
        if self._loaded:
            return self
        with self._load_lock:
            if self._loaded:
                return self
            t0 = time.perf_counter()
            import onnxruntime as ort
            from tokenizers import Tokenizer

            model_file = self.model_path / "model.onnx"
            if not model_file.exists():
                raise FileNotFoundError(
                    f"T1 model not found at {model_file}. Run `make models` or set T1_MODEL_PATH."
                )
            opts = ort.SessionOptions()
            opts.intra_op_num_threads = self.threads
            opts.inter_op_num_threads = 1
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            self._session = ort.InferenceSession(str(model_file), opts, providers=["CPUExecutionProvider"])
            tok = Tokenizer.from_file(str(self.model_path / "tokenizer.json"))
            tok.no_truncation()
            tok.no_padding()
            self._tokenizer = tok
            if self._injection_index is None:
                self._injection_index = _injection_index_from_config(self.model_path / "config.json")
            self._init_special_ids()
            self._loaded = True
            if self.warmup:
                self._score_unlocked(["warm-up: is this text a prompt injection?", "x " * 600])
            self.load_seconds = time.perf_counter() - t0
        return self

    def _init_special_ids(self) -> None:
        tok = self._tokenizer
        self._cls_id = tok.token_to_id("[CLS]")
        self._sep_id = tok.token_to_id("[SEP]")
        self._pad_id = tok.token_to_id("[PAD]") or 0
        if self._cls_id is None or self._sep_id is None:
            raise ValueError("tokenizer has no [CLS]/[SEP] tokens; wrong tokenizer.json?")
        if self._injection_index is None:
            self._injection_index = 1

    # -- public API ----------------------------------------------------------------------------

    def score(self, texts: list[str]) -> list[float]:
        return [r.score for r in self.score_detailed(texts)]

    def score_detailed(self, texts: list[str]) -> list[T1Result]:
        if not texts:
            return []
        self.load()
        with self._infer_lock:
            return self._score_unlocked(texts)

    # -- internals -----------------------------------------------------------------------------

    def _score_unlocked(self, texts: list[str]) -> list[T1Result]:
        encodings = self._tokenizer.encode_batch(list(texts), add_special_tokens=False)
        windows: list[tuple[int, list[int], tuple[int, int]]] = []  # (text index, ids, char span)
        meta: list[tuple[int, int]] = []  # per text: (total windows, scored windows)
        for ti, (text, enc) in enumerate(zip(texts, encodings, strict=True)):
            if not text or not text.strip():
                meta.append((0, 0))
                continue
            ids = enc.ids
            offsets = enc.offsets
            ranges, total = plan_windows(len(ids), self.window, self.overlap, self.max_windows_per_text)
            for start, end in ranges:
                end = min(end, len(ids))
                span = (offsets[start][0], offsets[end - 1][1]) if end > start else (0, len(text))
                windows.append((ti, [self._cls_id, *ids[start:end], self._sep_id], span))
            meta.append((total, len(ranges)))

        probs = np.zeros(len(windows), dtype=np.float32)
        if windows:
            lengths = [len(w[1]) for w in windows]
            for batch in make_batches(lengths, self.max_batch, self.max_batch_tokens):
                width = max(lengths[i] for i in batch)
                input_ids = np.full((len(batch), width), self._pad_id, dtype=np.int64)
                mask = np.zeros((len(batch), width), dtype=np.int64)
                for row, wi in enumerate(batch):
                    ids = windows[wi][1]
                    input_ids[row, : len(ids)] = ids
                    mask[row, : len(ids)] = 1
                (logits,) = self._session.run(["logits"], {"input_ids": input_ids, "attention_mask": mask})
                probs[batch] = softmax_injection(np.asarray(logits, dtype=np.float64), self._injection_index)

        best: list[tuple[float, tuple[int, int] | None]] = [(0.0, None)] * len(texts)
        for wi, (ti, _ids, span) in enumerate(windows):
            p = float(probs[wi])
            if best[ti][1] is None or p > best[ti][0]:
                best[ti] = (p, span)
        return [
            T1Result(score=best[i][0], windows=meta[i][0], windows_scored=meta[i][1], span=best[i][1])
            for i in range(len(texts))
        ]


def _injection_index_from_config(config_path: Path) -> int:
    try:
        cfg = json.loads(config_path.read_text())
        for idx, label in cfg.get("id2label", {}).items():
            if str(label).upper() == "INJECTION":
                return int(idx)
    except (OSError, ValueError):
        pass
    return 1


# ---------------------------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------------------------

_DEFAULT: InjectionClassifier | None = None
_DEFAULT_LOCK = threading.Lock()


def load_classifier(backend: str | None = None, **kwargs: Any) -> InjectionClassifier:
    """Create a T1 classifier. backend: "onnx" | "fake"; default from env T1_BACKEND, else "onnx".

    No silent fallback: if the ONNX model is missing, `score` raises and the pipeline applies the
    policy fail_mode. Use backend="fake" for offline tests.
    """
    backend = (backend or os.environ.get("T1_BACKEND") or "onnx").lower()
    if backend == "onnx":
        return OnnxInjectionClassifier(**kwargs)
    if backend == "fake":
        from bouncer.t1.fake import FakeInjectionClassifier

        return FakeInjectionClassifier(**kwargs)
    raise ValueError(f"unknown T1 backend {backend!r} (expected 'onnx' or 'fake')")


def get_classifier(factory: Callable[[], InjectionClassifier] | None = None) -> InjectionClassifier:
    """Process-wide singleton (the model is ~740 MB; load it once)."""
    global _DEFAULT
    if _DEFAULT is None:
        with _DEFAULT_LOCK:
            if _DEFAULT is None:
                _DEFAULT = (factory or load_classifier)()
    return _DEFAULT
