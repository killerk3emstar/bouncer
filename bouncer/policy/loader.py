"""Policy loading, validation with line numbers, hot reload, version history and diffs."""

from __future__ import annotations

import asyncio
import difflib
import logging
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from bouncer.policy.compiled import CompiledPolicy, compile_policy
from bouncer.policy.schema import PolicyDoc

log = logging.getLogger("bouncer.policy")


class PolicyError(Exception):
    def __init__(
        self,
        message: str,
        line: int | None = None,
        errors: list[dict[str, Any]] | None = None,
        path: str | None = None,
        column: int | None = None,
        value: str | None = None,
        snippet: list[dict[str, Any]] | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.line = line
        self.errors = errors or []
        self.path = path
        self.column = column
        self.value = value
        self.snippet = snippet or []

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "value": self.value,
            "snippet": self.snippet,
            "errors": self.errors,
        }


def _snippet(text: str, line: int | None, context: int = 2) -> list[dict[str, Any]]:
    if not line:
        return []
    lines = text.splitlines()
    lo, hi = max(1, line - context), min(len(lines), line + context)
    return [{"line": i, "text": lines[i - 1]} for i in range(lo, hi + 1)]


def _node_at(root: yaml.Node | None, loc: tuple[Any, ...]) -> tuple[int | None, int | None, str | None]:
    """Walk a composed YAML node tree along a pydantic error location.

    Returns (line, column, scalar value) of the deepest node found, 1-based."""
    node = root
    line = node.start_mark.line + 1 if node is not None else None
    col = node.start_mark.column + 1 if node is not None else None
    for part in loc:
        if node is None:
            break
        nxt = None
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                if str(k.value) == str(part):
                    nxt = v
                    line, col = k.start_mark.line + 1, k.start_mark.column + 1
                    break
        elif isinstance(node, yaml.SequenceNode) and isinstance(part, int) and part < len(node.value):
            nxt = node.value[part]
            line, col = nxt.start_mark.line + 1, nxt.start_mark.column + 1
        if nxt is None:
            break
        node = nxt
    value = None
    if isinstance(node, yaml.ScalarNode):
        value = str(node.value)
        line, col = node.start_mark.line + 1, node.start_mark.column + 1
    return line, col, value


def _node_line(root: yaml.Node | None, loc: tuple[Any, ...]) -> int | None:
    return _node_at(root, loc)[0]


def parse_policy(text: str) -> PolicyDoc:
    """Parse and validate policy text. Raises PolicyError with a line number."""
    try:
        raw = yaml.safe_load(text)
        root = yaml.compose(text)
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark or exc.context_mark
        line = mark.line + 1 if mark else None
        col = mark.column + 1 if mark else None
        raise PolicyError(f"YAML syntax error: {exc.problem or exc}", line, column=col, snippet=_snippet(text, line)) from exc
    if not isinstance(raw, dict):
        raise PolicyError("Policy must be a YAML mapping at the top level", 1, snippet=_snippet(text, 1))
    try:
        return PolicyDoc.model_validate(raw)
    except ValidationError as exc:
        errors = []
        for err in exc.errors():
            loc = tuple(p for p in err["loc"] if not (isinstance(p, str) and p.startswith("function-")))
            line, col, value = _node_at(root, loc)
            errors.append(
                {"loc": ".".join(str(p) for p in loc), "line": line, "column": col, "value": value, "message": err["msg"], "type": err["type"]}
            )
        first = errors[0]
        more = f" (+{len(errors) - 1} more)" if len(errors) > 1 else ""
        raise PolicyError(
            f"{first['message']}{more}",
            first["line"],
            errors,
            path=first["loc"] or None,
            column=first["column"],
            value=first["value"],
            snippet=_snippet(text, first["line"]),
        ) from exc


@dataclass
class PolicyVersion:
    version: str
    loaded_at: float
    text: str
    profile: str
    mode: str


class PolicyManager:
    """Holds the active CompiledPolicy and swaps it atomically on reload."""

    def __init__(
        self,
        path: str | Path,
        shared: dict[str, Any] | None = None,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
        history_size: int = 20,
    ) -> None:
        self.path = Path(path)
        self.shared = shared if shared is not None else {}
        self.on_event = on_event
        self.history: deque[PolicyVersion] = deque(maxlen=history_size)
        self.last_error: dict[str, Any] | None = None
        self.rejected: deque[dict[str, Any]] = deque(maxlen=history_size)
        self.last_reload_at: float | None = None
        self.reload_count = 0
        self.failed_count = 0
        self._current: CompiledPolicy | None = None
        self._overrides: dict[str, Any] | None = None

    @property
    def current(self) -> CompiledPolicy:
        assert self._current is not None, "policy not loaded"
        return self._current

    def load_initial(self) -> CompiledPolicy:
        text = self.path.read_text()
        doc = parse_policy(text)  # an invalid policy at startup is fatal
        self._activate(doc, text)
        return self.current

    def load_text(self, text: str, source: str = "inline") -> CompiledPolicy:
        """Activate policy text directly (tests, playground). Raises PolicyError."""
        doc = parse_policy(text)
        self._activate(doc, text, source=source)
        return self.current

    def _activate(self, doc: PolicyDoc, text: str, source: str | None = None) -> None:
        compiled = compile_policy(doc, text, source or str(self.path), self.shared)
        previous = self._current
        self._current = compiled
        self.last_reload_at = compiled.loaded_at
        self.history.appendleft(
            PolicyVersion(compiled.version, compiled.loaded_at, text, doc.profile, doc.defaults.mode)
        )
        if previous is not None and self.on_event:
            self.on_event(
                "policy.reloaded",
                {
                    "from_version": previous.version,
                    "to_version": compiled.version,
                    "diff": self.diff_text(previous.text, text),
                },
            )

    def reload(self) -> bool:
        """Re-read the file. On error keep the last good version and record the error."""
        try:
            text = self.path.read_text()
        except OSError as exc:
            self._fail(PolicyError(f"Cannot read policy file: {exc}"))
            return False
        if self._current is not None and text == self._current.text:
            if self.last_error is not None:  # the active version was restored after a rejected edit
                self.last_error = None
            return False
        try:
            doc = parse_policy(text)
            self._activate(doc, text)
        except PolicyError as exc:
            self._fail(exc, text)
            return False
        except Exception as exc:  # compile errors (bad regex etc.)
            self._fail(PolicyError(f"Policy failed to compile: {type(exc).__name__}: {exc}"), text)
            return False
        self.reload_count += 1
        self.last_error = None
        log.info("policy reloaded: %s", self.current.version)
        return True

    def _fail(self, exc: PolicyError, text: str | None = None) -> None:
        from bouncer.policy.compiled import policy_hash

        self.failed_count += 1
        self.last_error = {
            **exc.to_dict(),
            "at": time.time(),
            "active_version": self._current.version if self._current else None,
            "attempted_version": policy_hash(text) if text is not None else None,
        }
        if text is not None:
            self.rejected.appendleft(
                {
                    **self.last_error,
                    "text": text,
                    "diff": self.diff_text(self._current.text, text) if self._current else "",
                }
            )
        log.warning("policy reload rejected (%s, line %s): %s", exc.path, exc.line, exc.message)
        if self.on_event:
            self.on_event("policy.reload_failed", dict(self.last_error))

    @staticmethod
    def diff_text(old: str, new: str, old_name: str = "previous", new_name: str = "current") -> str:
        return "".join(
            difflib.unified_diff(
                old.splitlines(keepends=True), new.splitlines(keepends=True), old_name, new_name, n=2
            )
        )

    def diff(self, from_version: str, to_version: str) -> str | None:
        by_version = {v.version: v for v in self.history}
        a, b = by_version.get(from_version), by_version.get(to_version)
        if a is None or b is None:
            return None
        return self.diff_text(a.text, b.text, from_version, to_version)

    def versions(self) -> list[dict[str, Any]]:
        out = []
        items = list(self.history)
        for i, v in enumerate(items):
            prev = items[i + 1] if i + 1 < len(items) else None
            out.append(
                {
                    "version": v.version,
                    "loaded_at": v.loaded_at,
                    "profile": v.profile,
                    "mode": v.mode,
                    "active": i == 0,
                    "diff_from_previous": self.diff_text(prev.text, v.text, prev.version, v.version) if prev else None,
                }
            )
        return out

    async def watch(self, extra_paths: list[Path] | None = None, debounce_ms: int = 200) -> None:
        """Watch the policy directory and reload on change (runs until cancelled)."""
        from watchfiles import awatch

        paths = [self.path.parent] + [p for p in (extra_paths or []) if p.exists()]
        async for changes in awatch(*paths, debounce=debounce_ms, step=50):
            changed = {Path(p).resolve() for _, p in changes}
            if self.path.resolve() in changed:
                self.reload()
            hook = self.shared.get("on_files_changed")
            if hook:
                try:
                    hook(changed)
                except Exception:
                    log.exception("file change hook failed")
            await asyncio.sleep(0)
