"""Accuracy and latency per detection layer, per dataset, language, kind and technique.

    uv run python eval/run_eval.py                       # all datasets, default layers
    uv run python eval/run_eval.py --layers t1,t1_block --datasets bank_ops
    uv run python eval/run_eval.py --layers t1,mypkg.layers:make_t0   # plug in another layer

A layer is any object with `name: str` and `predict(texts) -> list[(flagged, score, latency_ms)]`:
flagged = the layer would stop or escalate the text; score in [0, 1] (use 1.0/0.0 for rule layers);
latency_ms = time spent on that text. Layers are registered in LAYERS (name -> factory) or given on
the command line as `module:attr`, where attr is a Layer, a Layer factory, or a factory returning
a list of Layers. T0, T2 and the combined pipeline are meant to be added that way, in process.

Writes reports/eval.json, reports/eval.md and reports/eval_predictions.jsonl (one row per text and
layer, for error analysis).
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import math
import platform
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DATASETS_DIR = ROOT / "eval" / "datasets"
REPORTS_DIR = ROOT / "reports"
POLICY_PATH = ROOT / "policy" / "bouncer.yaml"

Prediction = tuple[bool, float, float]  # (flagged, score, latency_ms)


@runtime_checkable
class Layer(Protocol):
    name: str

    def predict(self, texts: list[str]) -> list[Prediction]: ...


# ---------------------------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Example:
    id: str
    text: str
    label: str  # "injection" | "benign"
    lang: str
    kind: str
    source: str
    dataset: str
    technique: str | None = None
    channel: str | None = None

    @property
    def positive(self) -> bool:
        return self.label == "injection"


def load_datasets(names: Iterable[str] | None = None, limit: int | None = None) -> list[Example]:
    paths = sorted(DATASETS_DIR.glob("*.jsonl"))
    if names:
        wanted = set(names)
        paths = [p for p in paths if p.stem in wanted]
        missing = wanted - {p.stem for p in paths}
        if missing:
            raise SystemExit(f"unknown dataset(s): {sorted(missing)}; have {[p.stem for p in DATASETS_DIR.glob('*.jsonl')]}")
    out: list[Example] = []
    for path in paths:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if limit:
            rows = rows[:limit]
        for r in rows:
            if r["label"] not in ("injection", "benign"):
                raise ValueError(f"{path.name}:{r.get('id')}: bad label {r['label']!r}")
            out.append(
                Example(
                    id=r["id"], text=r["text"], label=r["label"], lang=r.get("lang", "en"),
                    kind=r.get("kind", "direct" if r["label"] == "injection" else "benign"),
                    source=r.get("source", path.stem), dataset=path.stem,
                    technique=r.get("technique"), channel=r.get("channel"),
                )
            )
    return out


# ---------------------------------------------------------------------------------------------
# Layers
# ---------------------------------------------------------------------------------------------


def policy_thresholds() -> dict[str, float]:
    """T1 thresholds from policy/bouncer.yaml (controls.prompt_injection.classifier)."""
    import yaml

    defaults = {"escalate_above": 0.50, "block_above": 0.98}
    try:
        policy = yaml.safe_load(POLICY_PATH.read_text())
        cfg = policy["controls"]["prompt_injection"]["classifier"]
        return {k: float(cfg.get(k, v)) for k, v in defaults.items()}
    except (OSError, KeyError, TypeError):
        return defaults


class CachedScorer:
    """Scores each text once, one text per call (the gateway's typical single-fragment case), and
    remembers score and latency so several threshold layers share one model pass."""

    def __init__(self, classifier: Any) -> None:
        self.classifier = classifier
        self.cache: dict[str, tuple[float, float]] = {}

    def get(self, texts: list[str]) -> list[tuple[float, float]]:
        for t in texts:
            if t not in self.cache:
                t0 = time.perf_counter()
                (s,) = self.classifier.score([t])
                self.cache[t] = (float(s), (time.perf_counter() - t0) * 1000)
        return [self.cache[t] for t in texts]


class ThresholdLayer:
    """flagged = score >= threshold."""

    def __init__(self, name: str, scorer: CachedScorer, threshold: float) -> None:
        self.name = name
        self.scorer = scorer
        self.threshold = threshold

    def predict(self, texts: list[str]) -> list[Prediction]:
        return [(s >= self.threshold, s, ms) for s, ms in self.scorer.get(texts)]


class RouteLayer:
    """T1 as the gateway routes it: flagged = T1 score >= escalate threshold OR not English
    (then T2 decides). Measures how much reaches T2 or a block, not a final decision."""

    def __init__(self, name: str, scorer: CachedScorer, threshold: float) -> None:
        from bouncer.t1.lang import is_probably_english

        self.name = name
        self.scorer = scorer
        self.threshold = threshold
        self._english = is_probably_english

    def predict(self, texts: list[str]) -> list[Prediction]:
        out = []
        for t, (s, ms) in zip(texts, self.scorer.get(texts), strict=True):
            t0 = time.perf_counter()
            non_en = not self._english(t)
            lang_ms = (time.perf_counter() - t0) * 1000
            out.append((s >= self.threshold or non_en, max(s, 1.0 if non_en else 0.0), ms + lang_ms))
        return out


_SCORER: CachedScorer | None = None


def _t1_scorer() -> CachedScorer:
    global _SCORER
    if _SCORER is None:
        from bouncer.t1 import load_classifier

        clf = load_classifier()
        if hasattr(clf, "load"):
            clf.load()
        _SCORER = CachedScorer(clf)
    return _SCORER


def _t1_layers() -> dict[str, Callable[[], Layer]]:
    th = policy_thresholds()
    return {
        "t1": lambda: ThresholdLayer(f"t1 (score >= {th['escalate_above']:g}, escalate)", _t1_scorer(), th["escalate_above"]),
        "t1_block": lambda: ThresholdLayer(f"t1 (score >= {th['block_above']:g}, block)", _t1_scorer(), th["block_above"]),
        "t1_route": lambda: RouteLayer(
            f"t1 routing (score >= {th['escalate_above']:g} or non-English -> T2/block)", _t1_scorer(), th["escalate_above"]
        ),
    }


LAYERS: dict[str, Callable[[], Layer | list[Layer]]] = {**_t1_layers()}
DEFAULT_LAYERS = ["t1", "t1_block", "t1_route"]


def register_layer(key: str, factory: Callable[[], Layer | list[Layer]]) -> None:
    """In-process registration for T0 / T2 / combined pipeline layers."""
    LAYERS[key] = factory


def resolve_layers(specs: list[str]) -> list[Layer]:
    layers: list[Layer] = []
    for spec in specs:
        if spec in LAYERS:
            obj: Any = LAYERS[spec]()
        elif ":" in spec:
            module, attr = spec.split(":", 1)
            obj = getattr(importlib.import_module(module), attr)
            if not isinstance(obj, Layer) and callable(obj):
                obj = obj()
        else:
            raise SystemExit(f"unknown layer {spec!r}; registered: {sorted(LAYERS)}; or use module:attr")
        layers.extend(obj if isinstance(obj, list) else [obj])
    for layer in layers:
        if not isinstance(layer, Layer):
            raise SystemExit(f"{layer!r} does not implement Layer (name + predict)")
    return layers


# ---------------------------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------------------------


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    k = (len(v) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def roc_auc(labels: list[bool], scores: list[float]) -> float | None:
    """Mann-Whitney U formulation with average ranks for ties."""
    pos = sum(labels)
    neg = len(labels) - pos
    if pos == 0 or neg == 0:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    rank_sum = sum(r for r, y in zip(ranks, labels, strict=True) if y)
    return (rank_sum - pos * (pos + 1) / 2) / (pos * neg)


def metrics(examples: list[Example], preds: list[Prediction]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for ex, (flag, _s, _ms) in zip(examples, preds, strict=True):
        if ex.positive and flag:
            tp += 1
        elif ex.positive:
            fn += 1
        elif flag:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else (0.0 if tp + fn and tp + fp else None)
    fpr = fp / (fp + tn) if fp + tn else None
    lat = [ms for _f, _s, ms in preds]
    return {
        "n": len(examples), "n_injection": tp + fn, "n_benign": fp + tn,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "roc_auc": roc_auc([e.positive for e in examples], [s for _f, s, _ms in preds]),
        "latency_ms_p50": percentile(lat, 0.5), "latency_ms_p95": percentile(lat, 0.95),
    }


SWEEP_THRESHOLDS = [0.5, 0.8, 0.9, 0.95, 0.98, 0.99, 0.995, 0.999]


def _graded(preds: list[Prediction]) -> bool:
    """True when the layer's scores carry more information than its flags (a classifier, not a rule)."""
    return len({round(s, 6) for _f, s, _ms in preds}) > 2


def sweep(examples: list[Example], preds: list[Prediction]) -> dict[str, Any]:
    """Metrics if the decision were `score >= t`, for each t in SWEEP_THRESHOLDS."""
    return {f"{t:g}": metrics(examples, [(s >= t, s, ms) for _f, s, ms in preds]) for t in SWEEP_THRESHOLDS}


def grouped(examples: list[Example], preds: list[Prediction], key: Callable[[Example], str | None]) -> dict[str, Any]:
    groups: dict[str, list[int]] = {}
    for i, ex in enumerate(examples):
        k = key(ex)
        if k is not None:
            groups.setdefault(k, []).append(i)
    return {k: metrics([examples[i] for i in idx], [preds[i] for i in idx]) for k, idx in sorted(groups.items())}


# ---------------------------------------------------------------------------------------------
# Run and report
# ---------------------------------------------------------------------------------------------


def hardware() -> str:
    cpu = platform.processor() or platform.machine()
    if sys.platform == "darwin":
        try:
            cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout.strip()
            mem = int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True).stdout) // 2**30
            cpu = f"{cpu}, {mem} GB RAM"
        except (OSError, ValueError):
            pass
    return f"{cpu}, {platform.system()} {platform.release()}, Python {platform.python_version()}"


def run(layers: list[Layer], examples: list[Example], batch_size: int = 32) -> dict[str, Any]:
    datasets = sorted({e.dataset for e in examples})
    result: dict[str, Any] = {
        "generated": dt.datetime.now().isoformat(timespec="seconds"),
        "hardware": hardware(),
        "datasets": {d: sum(e.dataset == d for e in examples) for d in datasets},
        "layers": {},
    }
    predictions: dict[str, list[Prediction]] = {}
    for layer in layers:
        preds: list[Prediction] = []
        t0 = time.perf_counter()
        for i in range(0, len(examples), batch_size):
            chunk = examples[i : i + batch_size]
            out = layer.predict([e.text for e in chunk])
            if len(out) != len(chunk):
                raise RuntimeError(f"layer {layer.name} returned {len(out)} predictions for {len(chunk)} texts")
            preds.extend((bool(f), float(s), float(ms)) for f, s, ms in out)
        wall = time.perf_counter() - t0
        predictions[layer.name] = preds
        per_dataset = {}
        for d in datasets:
            idx = [i for i, e in enumerate(examples) if e.dataset == d]
            ex = [examples[i] for i in idx]
            pr = [preds[i] for i in idx]
            per_dataset[d] = {
                "all": metrics(ex, pr),
                "by_lang": grouped(ex, pr, lambda e: e.lang),
                "by_kind": grouped(ex, pr, lambda e: e.kind),
                "by_lang_kind": grouped(ex, pr, lambda e: f"{e.lang} / {e.kind}"),
                "by_technique": grouped(ex, pr, lambda e: e.technique),
                "by_channel": grouped(ex, pr, lambda e: e.channel),
            }
            if _graded(pr):
                per_dataset[d]["threshold_sweep"] = sweep(ex, pr)
        result["layers"][layer.name] = {
            "all": metrics(examples, preds),
            "by_lang": grouped(examples, preds, lambda e: e.lang),
            "datasets": per_dataset,
            "wall_seconds": wall,
        }
    result["_predictions"] = predictions
    return result


def _f(v: Any, pct: bool = True) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v * 100:.1f}" if pct else f"{v:.1f}"
    return str(v)


def table(rows: dict[str, dict[str, Any]], first_col: str) -> list[str]:
    head = f"| {first_col} | n | inj | benign | TP | FP | FN | TN | precision % | recall % | F1 % | FPR % | AUC | p50 ms | p95 ms |"
    lines = [head, "|" + "---|" * 15]
    for k, m in rows.items():
        auc = "-" if m["roc_auc"] is None else f"{m['roc_auc']:.3f}"
        lines.append(
            f"| {k} | {m['n']} | {m['n_injection']} | {m['n_benign']} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | "
            f"{_f(m['precision'])} | {_f(m['recall'])} | {_f(m['f1'])} | {_f(m['fpr'])} | {auc} | "
            f"{_f(m['latency_ms_p50'], False)} | {_f(m['latency_ms_p95'], False)} |"
        )
    return lines


def to_markdown(result: dict[str, Any], examples: list[Example]) -> str:
    out = [
        "# Detection eval",
        "",
        f"Generated {result['generated']} by `eval/run_eval.py` on {result['hardware']}.",
        "Datasets: " + ", ".join(f"`{d}` ({n})" for d, n in result["datasets"].items()) + ". See `eval/datasets/README.md`.",
        "",
        "Positive class = injection. Recall on a group with only attacks is the detection rate; FPR on a group with",
        "only benign texts is the false-alarm rate. Latency is per text (one text per call), model already loaded.",
        "",
    ]
    for name, lr in result["layers"].items():
        out += [f"## Layer: {name}", "", f"Wall time {lr['wall_seconds']:.1f} s.", ""]
        out += table({"all datasets": lr["all"]} | {f"`{d}`": v["all"] for d, v in lr["datasets"].items()}, "dataset")
        out += ["", "By language (all datasets):", ""]
        out += table(lr["by_lang"], "lang")
        sweeps_done: set[tuple[float, ...]] = set()
        scores_key = tuple(round(s, 6) for _f, s, _ms in result["_predictions"][name])
        for d, v in lr["datasets"].items():
            out += ["", f"`{d}` by language and kind:", ""]
            out += table(v["by_lang_kind"], "lang / kind")
            if "threshold_sweep" in v and scores_key not in sweeps_done:
                out += ["", f"`{d}` threshold sweep on the layer score (decision = score >= threshold):", ""]
                out += table(v["threshold_sweep"], "threshold")
            if v["by_technique"]:
                out += ["", f"`{d}` by obfuscation / jailbreak technique (attacks only):", ""]
                out += table(v["by_technique"], "technique")
            if len(v["by_channel"]) > 1:
                out += ["", f"`{d}` by channel:", ""]
                out += table(v["by_channel"], "channel")
        sweeps_done.add(scores_key)
        # Error analysis on our own dataset only (public sets: ids only, see eval_predictions.jsonl).
        preds = result["_predictions"][name]
        fps = [(e, p) for e, p in zip(examples, preds, strict=True) if not e.positive and p[0] and e.dataset == "bank_ops"]
        fns = [(e, p) for e, p in zip(examples, preds, strict=True) if e.positive and not p[0] and e.dataset == "bank_ops"]
        if fps:
            out += ["", f"False positives on `bank_ops` ({len(fps)}):", ""]
            for e, p in fps:
                out.append(f"- `{e.id}` ({e.lang}, {e.kind}, score {p[1]:.3f}): {_short(e.text)}")
        if fns:
            out += ["", f"Missed attacks on `bank_ops` ({len(fns)}), ids and technique only:", ""]
            out.append(", ".join(f"`{e.id}` ({e.technique or e.kind}, {p[1]:.2f})" for e, p in fns))
        out.append("")
    return "\n".join(out) + "\n"


def _short(text: str, n: int = 90) -> str:
    t = " ".join(text.split())
    t = t.replace("|", "/")
    return t if len(t) <= n else t[: n - 3] + "..."


def write_reports(result: dict[str, Any], examples: list[Example], prefix: str = "eval") -> None:
    (REPORTS_DIR / prefix).parent.mkdir(parents=True, exist_ok=True)
    preds = result.pop("_predictions")
    (REPORTS_DIR / f"{prefix}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    result["_predictions"] = preds
    (REPORTS_DIR / f"{prefix}.md").write_text(to_markdown(result, examples))
    with (REPORTS_DIR / f"{prefix}_predictions.jsonl").open("w", encoding="utf-8") as fh:
        for name, pr in preds.items():
            for e, (flag, score, ms) in zip(examples, pr, strict=True):
                fh.write(json.dumps({"layer": name, "id": e.id, "dataset": e.dataset, "label": e.label, "lang": e.lang,
                                     "kind": e.kind, "flagged": flag, "score": round(score, 6),
                                     "latency_ms": round(ms, 3)}) + "\n")
    result.pop("_predictions")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--layers", default=",".join(DEFAULT_LAYERS), help="comma-separated registered names or module:attr")
    ap.add_argument("--datasets", default="", help="comma-separated dataset names (file stems); default all")
    ap.add_argument("--limit", type=int, default=None, help="max rows per dataset (smoke runs)")
    ap.add_argument("--out", default="eval", help="report file prefix in reports/")
    args = ap.parse_args(argv)

    examples = load_datasets([d for d in args.datasets.split(",") if d] or None, args.limit)
    layers = resolve_layers([s for s in args.layers.split(",") if s])
    result = run(layers, examples)
    write_reports(result, examples, args.out)
    for name, lr in result["layers"].items():
        m = lr["all"]
        print(f"{name}: n={m['n']} precision={_f(m['precision'])}% recall={_f(m['recall'])}% "
              f"FPR={_f(m['fpr'])}% p50={_f(m['latency_ms_p50'], False)} ms p95={_f(m['latency_ms_p95'], False)} ms")
    print(f"wrote reports/{args.out}.md, reports/{args.out}.json, reports/{args.out}_predictions.jsonl")


if __name__ == "__main__":
    main()
