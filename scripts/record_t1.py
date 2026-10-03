"""Record real T1 scores for the offline test fixture (tests/fixtures/t1_scores.json).

`make test` runs without the model: FakeInjectionClassifier looks up these recorded scores by the
sha256 of the exact text. Run this after adding or changing test cases (needs the ONNX model):

    uv run python scripts/record_t1.py                       # texts from tests/cases/*.yaml
    uv run python scripts/record_t1.py --text "some text"    # plus extra texts
    uv run python scripts/record_t1.py --extra texts.txt     # one text per line, or JSONL {"text": ...}
    uv run python scripts/record_t1.py --from-dump misses.jsonl   # texts the fake missed (T1_FAKE_MISSES)

Texts collected from a case: every string under `content`, `description` or `text` keys (message
contents, tool results, tool descriptions, guard-API input), in `request` and in each of `steps`.
Model output (`mock_response`), expectations and judge stubs are skipped. When NFKC normalization or
removing invisible characters changes a text, the normalized form is recorded too, since the
pipeline may hand T1 the normalized view. Existing entries are kept unless --prune is given.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import unicodedata
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bouncer.t1.classifier import MODEL_ID, OnnxInjectionClassifier  # noqa: E402
from bouncer.t1.fake import DEFAULT_FIXTURE, text_key  # noqa: E402

TEXT_KEYS = {"content", "description", "text"}
SKIP_KEYS = {"expect", "mock_response", "judge", "judge_error", "policy_patch"}
INVISIBLE = {"​", "‌", "‍", "⁠", "﻿", "­"}


def _strings(node: Any, under_text_key: bool = False) -> Iterator[str]:
    if isinstance(node, str):
        if under_text_key:
            yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            if key in SKIP_KEYS:
                continue
            yield from _strings(value, under_text_key or key in TEXT_KEYS)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item, under_text_key)


def texts_from_case(case: dict[str, Any]) -> list[str]:
    out: list[str] = []
    parts = [case.get("request")] + [s.get("request", s) for s in case.get("steps") or [] if isinstance(s, dict)]
    for part in parts:
        if part is not None:
            out.extend(_strings(part))
    return out


def texts_from_cases(cases_dir: Path) -> list[str]:
    import yaml

    texts: list[str] = []
    for path in sorted(cases_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for case in data if isinstance(data, list) else [data]:
            if isinstance(case, dict):
                texts.extend(texts_from_case(case))
    return texts


def texts_from_file(path: Path) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        if line.lstrip().startswith("{"):
            try:
                out.append(json.loads(line)["text"])
                continue
            except (ValueError, KeyError):
                pass
        out.append(line)
    return out


def normalized(text: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFKC", text) if ch not in INVISIBLE)


def unique(texts: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for t in texts:
        if t and t.strip():
            seen.setdefault(t, None)
            n = normalized(t)
            if n != t and n.strip():
                seen.setdefault(n, None)
    return list(seen)


def preview(text: str, n: int = 60) -> str:
    t = " ".join(text.split())
    return t if len(t) <= n else t[: n - 3] + "..."


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases-dir", type=Path, default=ROOT / "tests" / "cases")
    ap.add_argument("--extra", type=Path, action="append", default=[], help="text file or JSONL with texts")
    ap.add_argument("--from-dump", type=Path, action="append", default=[], help="JSONL written via T1_FAKE_MISSES")
    ap.add_argument("--text", action="append", default=[], help="a text to record (repeatable)")
    ap.add_argument("--out", type=Path, default=DEFAULT_FIXTURE)
    ap.add_argument("--prune", action="store_true", help="drop recorded entries not in the current text set")
    ap.add_argument("--dry-run", action="store_true", help="list how many texts would be scored, do not load the model")
    args = ap.parse_args(argv)

    texts: list[str] = []
    if args.cases_dir.exists():
        texts += texts_from_cases(args.cases_dir)
    for path in [*args.extra, *args.from_dump]:
        texts += texts_from_file(path)
    texts += args.text
    texts = unique(texts)

    existing: dict[str, Any] = {}
    if args.out.exists():
        existing = json.loads(args.out.read_text(encoding="utf-8")).get("scores", {})
    wanted = {text_key(t): t for t in texts}
    todo = [t for k, t in wanted.items() if k not in existing]
    print(f"{len(texts)} texts collected, {len(todo)} not yet recorded, {len(existing)} entries in {args.out.name}")
    if args.dry_run:
        return

    scores = {} if args.prune else dict(existing)
    if args.prune:
        scores.update({k: v for k, v in existing.items() if k in wanted})
    if todo:
        clf = OnnxInjectionClassifier().load()
        for t, s in zip(todo, clf.score(todo), strict=True):
            scores[text_key(t)] = {"score": round(float(s), 6), "preview": preview(t)}

    from eval.run_eval import hardware

    payload = {
        "model": MODEL_ID,
        "note": "Recorded real T1 scores keyed by sha256(utf-8 text). Generated by scripts/record_t1.py; do not edit by hand.",
        "recorded": dt.datetime.now().isoformat(timespec="seconds"),
        "hardware": hardware(),
        "count": len(scores),
        "scores": dict(sorted(scores.items())),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(scores)} entries to {args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out}")


if __name__ == "__main__":
    main()
