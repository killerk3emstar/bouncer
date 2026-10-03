"""Judge backends. All of them return the same normalized answer shape (see base.py)."""

from __future__ import annotations

import os

from judge.backends.base import Backend, BackendError, Decision, QuestionError

BACKENDS = ("clef-mlx", "ollama-guard", "fake")


def make_backend(name: str | None = None) -> Backend:
    """Build a backend from its name, reading model locations from the environment.

    JUDGE_BACKEND   clef-mlx | ollama-guard | fake        (default clef-mlx)
    CLEF_MLX_PATH   path to the MLX Clef checkpoint        (default models/clef-flash-mlx-4bit)
    OLLAMA_URL      Ollama base URL                        (default http://localhost:11434)
    OLLAMA_GUARD_MODEL                                     (default llama-guard3:1b)
    JUDGE_MAX_TOKENS  max prompt tokens for Clef           (default 1536, about 3.6 s on an M4 Pro)
    """
    name = (name or os.environ.get("JUDGE_BACKEND") or "clef-mlx").strip().lower()
    if name == "fake":
        from judge.backends.fake import FakeBackend

        return FakeBackend()
    if name == "clef-mlx":
        from judge.backends.clef_mlx import ClefMLXBackend

        return ClefMLXBackend(
            path=os.environ.get("CLEF_MLX_PATH", "models/clef-flash-mlx-4bit"),
            max_tokens=int(os.environ.get("JUDGE_MAX_TOKENS", "1536")),
        )
    if name == "ollama-guard":
        from judge.backends.ollama_guard import OllamaGuardBackend

        return OllamaGuardBackend(
            url=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
            model=os.environ.get("OLLAMA_GUARD_MODEL", "llama-guard3:1b"),
        )
    raise ValueError(f"unknown judge backend {name!r}; expected one of {', '.join(BACKENDS)}")


__all__ = ["BACKENDS", "Backend", "BackendError", "Decision", "QuestionError", "make_backend"]
