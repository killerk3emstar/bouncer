"""MLX port of Clef / Clef-Flash record encoding and joint schema head.

Vendored from ``clef_mlx.py`` in https://huggingface.co/TrevorJS/clef-flash-mlx-4bit (Apache-2.0),
itself a port of Cloudflare's Apache-2.0 ``joint_schema_model.py`` from
https://huggingface.co/Cloudflare/clef-flash. Copyright the original authors; see the LICENSE file
shipped with the checkpoint (models/clef-flash-mlx-4bit/LICENSE).

Changes from the upstream file:
- ``encode_record`` also returns how many state tokens were dropped by truncation.
- ``load`` only accepts a local directory (no hub download at serve time).
- the JevBench helper ``read_one_clef`` is removed.
The head math is unchanged.
"""

from __future__ import annotations

import json
import math
import os

import mlx.core as mx
import mlx.nn as nn
import numpy as np

SYSTEM_PROMPT = ("Read the complete state and schema. Decide every field jointly. Each answer "
                 "must be exactly one of that field's allowed options.")
QUESTION_TYPES = {"noul": 0, "choice": 1, "score": 2}


def render(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def question_options(question):
    t = str(question["type"])
    if t == "noul":
        c = {"true": "The proposition is true or the answer is yes.", "false": "The proposition is false or the answer is no."}
        c.update(question.get("criteria") or {})
        return [(k, c[k]) for k in ("true", "false")]
    if t == "choice":
        return sorted((str(k), v) for k, v in question["criteria"].items())
    return [(str(i), v) for i, v in enumerate(question["criteria"])]


def encode_schema(tok, questions):
    """Schema token ids and per-question spans relative to the schema start."""
    T = lambda s: tok.encode(s, add_special_tokens=False)  # noqa: E731
    schema = T("\n\nSCHEMA FIELDS:\n")
    qs = []
    for qi, (qid, q) in enumerate(questions.items()):
        schema += T(f"\nFIELD {qi + 1}\nID: {qid}\nTYPE: {q['type']}\nINSTRUCTION: ")
        q0 = len(schema)
        schema += T(render(q.get("instructions") or str(qid)))
        q1 = len(schema)
        schema += T("\nALLOWED OPTIONS:\n")
        spans, oids = [], []
        for oi, (oid, desc) in enumerate(question_options(q)):
            schema += T(f"OPTION {oi + 1}: ")
            s0 = len(schema)
            sem = {"option_id": oid}
            if desc is not None:
                sem["description"] = desc
            schema += T(render(sem))
            spans.append((s0, len(schema)))
            oids.append(oid)
            schema += T("\n")
        schema += T("END FIELD\n")
        qs.append({"type": QUESTION_TYPES[str(q["type"])], "qspan": (q0, q1), "ospans": spans, "oids": oids})
    return schema, qs


def frame(tok):
    T = lambda s: tok.encode(s, add_special_tokens=False)  # noqa: E731
    prefix = T(f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\nSTATE:\n")
    suffix = T("\n<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\nJOINT SCHEMA DECISIONS:")
    return prefix, suffix


def encode_record(tok, record, max_length=16384):
    """Token ids, per-question spans (release layout) and the number of state tokens dropped."""
    schema, qs = encode_schema(tok, record["questions"])
    prefix, suffix = frame(tok)
    full_state = tok.encode(render(record["state"]), add_special_tokens=False)
    budget = max(0, max_length - len(prefix) - len(schema) - len(suffix))
    state = full_state[:budget]
    off = len(prefix) + len(state)
    for q in qs:
        q["qspan"] = (q["qspan"][0] + off, q["qspan"][1] + off)
        q["ospans"] = [(a + off, b + off) for a, b in q["ospans"]]
    return prefix + state + schema + suffix, qs, len(full_state) - len(state)


# ---------- joint schema head (torch module semantics, float32) ----------

def _ln(W, p, x, eps=1e-5):
    mu = x.mean(-1, keepdims=True)
    var = ((x - mu) ** 2).mean(-1, keepdims=True)
    return (x - mu) * mx.rsqrt(var + eps) * W[p + ".weight"] + W[p + ".bias"]


def _lin(W, p, x, bias=True):
    y = x @ W[p + ".weight"].T
    return y + W[p + ".bias"] if bias else y


def _mha(W, p, q_in, kv_in, heads):
    """torch.nn.MultiheadAttention (batch_first, no masks) for one sequence: q_in (Lq, w), kv_in (Lk, w)."""
    w = q_in.shape[-1]
    d = w // heads
    Wq, Wk, Wv = mx.split(W[p + ".in_proj_weight"], 3, axis=0)
    bq, bk, bv = mx.split(W[p + ".in_proj_bias"], 3)
    sh = lambda x: x.reshape(x.shape[0], heads, d).transpose(1, 0, 2)[None]  # noqa: E731
    q, k, v = sh(q_in @ Wq.T + bq), sh(kv_in @ Wk.T + bk), sh(kv_in @ Wv.T + bv)
    o = mx.fast.scaled_dot_product_attention(q, k, v, scale=1.0 / math.sqrt(d))[0].transpose(1, 0, 2).reshape(-1, w)
    return _lin(W, p + ".out_proj", o)


def _normalize(x, eps=1e-12):
    return x / mx.maximum(mx.linalg.norm(x, axis=-1, keepdims=True), eps)


class JointSchemaHead:
    def __init__(self, path):
        with open(os.path.join(path, "joint_head_config.json")) as f:
            self.cfg = json.load(f)
        self.W = {k: v.astype(mx.float32) for k, v in mx.load(os.path.join(path, "joint_head.safetensors")).items()}

    def __call__(self, hidden, ids, qs, lexical_rows):
        """hidden (L, H) final backbone states; lexical_rows(token_ids) -> output-embedding rows. Returns logits per question."""
        W, c = self.W, self.cfg
        heads = c["heads"]
        w = c["width"]
        h = _ln(W, "hidden_norm", hidden.astype(mx.float32))
        memory = _lin(W, "memory_projection", h, bias=False)
        g = h[-1]
        span = lambda a, b: h[a:b].mean(0)  # noqa: E731
        qv = mx.stack([span(*q["qspan"]) for q in qs])
        types = mx.array([q["type"] for q in qs])
        ctx = [mx.stack([span(a, b) for a, b in q["ospans"]]) for q in qs]
        lex = [mx.stack([lexical_rows(ids[a:b]).astype(mx.float32).mean(0) for a, b in q["ospans"]]) for q in qs]
        queries = mx.concatenate([_lin(W, "option_context_projection", cx, False) + _lin(W, "option_lexical_projection", lx, False)
                                  + _lin(W, "option_question_projection", qv[i], False)[None] for i, (cx, lx) in enumerate(zip(ctx, lex, strict=True))])
        for i in range(c["routing_layers"]):
            p = f"evidence_layers.{i}"
            mem = _ln(W, p + ".memory_norm", memory)
            queries = queries + _mha(W, p + ".attention", _ln(W, p + ".query_norm", queries), mem, heads)
            f = _ln(W, p + ".feedforward_norm", queries)
            queries = queries + _lin(W, p + ".feedforward.3", nn.gelu(_lin(W, p + ".feedforward.0", f)))
        counts = [len(q["ospans"]) for q in qs]
        split = mx.split(queries, list(np.cumsum(counts)[:-1]), axis=0) if len(counts) > 1 else [queries]
        base = _lin(W, "question_projection", qv, False)
        summ = mx.stack([(mx.softmax(o @ base[i] / math.sqrt(w), axis=0)[:, None] * o).sum(0) for i, o in enumerate(split)])
        fields = base + _ln(W, "option_summary_norm", summ) + _lin(W, "global_projection", g, False)[None] + W["type_embedding.weight"][types]
        for i in range(c["layers"]):
            p = f"layers.{i}"
            x = _ln(W, p + ".norm1", fields)
            fields = fields + _mha(W, p + ".self_attn", x, x, heads)
            fields = fields + _mha(W, p + ".multihead_attn", _ln(W, p + ".norm2", fields), memory, heads)
            fields = fields + _lin(W, p + ".linear2", nn.gelu(_lin(W, p + ".linear1", _ln(W, p + ".norm3", fields))))
        fields = _ln(W, "field_norm", fields)
        prior_scale = mx.exp(mx.minimum(W["prior_logit_scale"], math.log(100.0)))
        joint_scale = mx.exp(mx.minimum(W["joint_logit_scale"], math.log(100.0)))
        gate = mx.sigmoid(W["residual_gate"])
        out = []
        for i, (_q, o) in enumerate(zip(qs, split, strict=True)):
            anchor = _normalize(qv[i] + g)
            prior = prior_scale * (_normalize(lex[i]) @ anchor)
            o = _ln(W, "option_norm", o)
            f = mx.broadcast_to(fields[i], o.shape)
            cos = (f * o).sum(-1) / mx.maximum(mx.linalg.norm(f, axis=-1) * mx.linalg.norm(o, axis=-1), 1e-8)
            feats = mx.concatenate([f, o, f * o, mx.abs(f - o)], axis=-1)
            resid = _lin(W, "residual_scorer.3", nn.gelu(_lin(W, "residual_scorer.0", feats)))[:, 0]
            out.append(prior + gate * (joint_scale * cos + resid))
        return out


def lexical_fn(model):
    """Rows of the output embedding (lm_head) for a list of token ids, dequantised if the head is quantised."""
    lm = model.language_model.lm_head if hasattr(model.language_model, "lm_head") else model.language_model.model.embed_tokens
    if hasattr(lm, "scales"):
        return lambda t: mx.dequantize(lm.weight[mx.array(t)], lm.scales[mx.array(t)], lm.biases[mx.array(t)],
                                       group_size=lm.group_size, bits=lm.bits)
    return lambda t: lm.weight[mx.array(t)]


def load(path):
    """(model, tokenizer, head, lexical) from a local directory holding an MLX backbone plus joint_head.*"""
    from mlx_lm import load as mlx_load

    model, tok = mlx_load(path)
    return model, tok, JointSchemaHead(path), lexical_fn(model)
