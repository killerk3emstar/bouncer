# Eval: detection accuracy and latency per layer

```
make eval                                              # T1 and T0 on bank_ops + deepset_test -> reports/eval_quick.*
make eval-full                                         # adds the full pipeline with the judge -> reports/eval_layers.*
uv run python eval/run_eval.py                         # all datasets, T1 layers; needs the ONNX model
T1_BACKEND=fake uv run python eval/run_eval.py         # same pipeline without the model (smoke test)
uv run python eval/run_eval.py --datasets bank_ops --layers t1 --limit 50
uv run python eval/bench_t1.py --iters 30              # T1 latency, writes reports/t1_bench.json
```

Outputs (prefix `eval` by default, set with `--out`):
- `reports/eval.md`: tables per layer: per dataset, per language, per language and kind, per
  obfuscation or jailbreak technique, per channel, a threshold sweep for score-based layers, and the
  false positives and missed attacks on `bank_ops`.
- `reports/eval.json`: the same numbers, machine-readable (for slides and the dashboard).
- `reports/eval_predictions.jsonl`: one line per text and layer (id, label, flagged, score,
  latency), for error analysis.

Metrics: precision, recall, F1, false-positive rate (FPR), ROC AUC from the layer score, and
latency p50/p95 per text. Positive class = injection. Latency is measured per text, one text per
call, with the model already loaded.

Datasets: `eval/datasets/*.jsonl`, described with licenses in `eval/datasets/README.md`.

## Layers

| key | what it measures |
|---|---|
| `t1` | T1 classifier, flagged when score >= `controls.prompt_injection.classifier.escalate_above` (policy, 0.50) |
| `t1_block` | T1 classifier, flagged when score >= `block_above` (policy; 1.0 in the shipped policy, where T1 never blocks on its own; `reports/eval.md` was generated when it was 0.98) |
| `t1_route` | what T1 lets through without review: flagged when score >= escalate threshold or the text is not English (`bouncer.t1.lang`); flagged texts go to T2 or are blocked. Its FPR is the T2 load on benign traffic, not a false-block rate |
| `eval.layers:t0` | T0 only: each text through the real gateway code (`/v1/guard/check` in-process, principal `playground`), T1 off, judge off; indirect-injection texts are sent as `web.fetch` results, the rest as user messages; flagged when the decision is block or require_approval from an attack control (`prompt_injection`, `signatures`, `obfuscation`, `supply_chain`) |
| `eval.layers:pipeline` | the same with T1 (ONNX) and the judge from the policy (needs `make judge`) |

Thresholds are read from `policy/bouncer.yaml` at start.

## Adding a layer

A layer is any object with:

```python
name: str
def predict(self, texts: list[str]) -> list[tuple[bool, float, float]]:
    # (flagged, score in [0, 1], latency_ms) per text, same order
```

Either register it in process:

```python
from eval.run_eval import register_layer, main
register_layer("t0", lambda: T0Layer(policy))
main(["--layers", "t0,t1,combined"])
```

or name it on the command line as `module:attr`, where `attr` is a layer object, a factory, or a
factory returning a list of layers:

```
uv run python eval/run_eval.py --layers t1,eval.layers:t0,eval.layers:pipeline
```

Rule layers can return score 1.0 / 0.0; the threshold sweep is only printed for layers whose scores
take more than two values.
