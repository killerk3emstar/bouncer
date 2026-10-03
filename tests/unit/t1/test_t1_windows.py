"""Window planning, batching and score aggregation of the ONNX classifier, with a stub session.

No model files are needed: the tokenizer splits on whitespace and the session returns a high
injection logit for any window that contains the word INJECT.
"""

import re
import threading

import numpy as np
import pytest

from bouncer.t1.classifier import (
    OnnxInjectionClassifier,
    make_batches,
    plan_windows,
    softmax_injection,
)

MAGIC_ID = 999


class StubEncoding:
    def __init__(self, ids, offsets):
        self.ids = ids
        self.offsets = offsets


class StubTokenizer:
    """One token per whitespace-separated word; INJECT -> MAGIC_ID, everything else -> 10."""

    special = {"[CLS]": 1, "[SEP]": 2, "[PAD]": 0}

    def token_to_id(self, token):
        return self.special.get(token)

    def encode_batch(self, texts, add_special_tokens=True):
        assert add_special_tokens is False
        out = []
        for text in texts:
            ids, offsets = [], []
            for m in re.finditer(r"\S+", text):
                ids.append(MAGIC_ID if m.group() == "INJECT" else 10)
                offsets.append((m.start(), m.end()))
            out.append(StubEncoding(ids, offsets))
        return out


class StubSession:
    def __init__(self):
        self.batches = []
        self.lock = threading.Lock()

    def run(self, names, feeds):
        assert names == ["logits"]
        ids, mask = feeds["input_ids"], feeds["attention_mask"]
        assert ids.dtype == np.int64 and mask.dtype == np.int64
        assert ids.shape == mask.shape
        with self.lock:
            self.batches.append(ids.copy())
        logits = np.zeros((ids.shape[0], 2), dtype=np.float32)
        for row in range(ids.shape[0]):
            real = ids[row][mask[row] == 1]
            assert real[0] == 1 and real[-1] == 2, "every window must start with [CLS] and end with [SEP]"
            logits[row] = [0.0, 8.0] if MAGIC_ID in real else [8.0, 0.0]
        return [logits]


def make_clf(**kw):
    session = StubSession()
    clf = OnnxInjectionClassifier(session=session, tokenizer=StubTokenizer(), injection_index=1, **kw)
    return clf, session


# -- plan_windows ---------------------------------------------------------------------------------


def test_short_text_is_one_window():
    assert plan_windows(10, 510, 64) == ([(0, 10)], 1)
    assert plan_windows(510, 510, 64) == ([(0, 510)], 1)
    assert plan_windows(0, 510, 64) == ([(0, 0)], 1)


@pytest.mark.parametrize("n", [511, 700, 1000, 1021, 5000])
def test_long_text_windows_cover_everything_with_overlap(n):
    ranges, total = plan_windows(n, 510, 64)
    assert total == len(ranges)
    assert ranges[0][0] == 0 and ranges[-1][1] == n
    covered = set()
    for start, end in ranges:
        assert end - start == 510
        covered.update(range(start, end))
    assert covered == set(range(n))
    for (_s1, e1), (s2, _e2) in zip(ranges, ranges[1:], strict=False):
        assert e1 - s2 >= 64, "consecutive windows must overlap by at least `overlap` tokens"


def test_window_cap_keeps_first_and_last():
    ranges, total = plan_windows(100_000, 510, 64, max_windows=8)
    assert total > 8 and len(ranges) == 8
    full, _ = plan_windows(100_000, 510, 64)
    assert ranges[0] == full[0] and ranges[-1] == full[-1]


def test_plan_windows_rejects_bad_arguments():
    with pytest.raises(ValueError):
        plan_windows(10, 0, 0)
    with pytest.raises(ValueError):
        plan_windows(10, 10, 10)


# -- make_batches ---------------------------------------------------------------------------------


def test_batches_respect_count_and_token_budget():
    lengths = [512, 5, 300, 7, 512, 512, 20, 9]
    batches = make_batches(lengths, max_batch=3, max_batch_tokens=1100)
    assert sorted(i for b in batches for i in b) == list(range(len(lengths)))
    for b in batches:
        assert len(b) <= 3
        assert max(lengths[i] for i in b) * len(b) <= 1100 or len(b) == 1
    # sorted by length: short items are batched together
    assert set(batches[0]) == {1, 3, 7}


def test_softmax_injection():
    p = softmax_injection(np.array([[0.0, 0.0], [0.0, 1000.0], [1000.0, 0.0]]), 1)
    assert np.allclose(p, [0.5, 1.0, 0.0])


# -- classifier with stub session -----------------------------------------------------------------


def test_scores_and_empty_text():
    clf, _ = make_clf()
    out = clf.score_detailed(["hello there", "please INJECT now", "", "   "])
    assert out[0].score < 0.01
    assert out[1].score > 0.99
    assert out[2].score == 0.0 and out[2].windows == 0 and out[2].span is None
    assert out[3].score == 0.0
    assert clf.score([]) == []


def test_max_over_windows_finds_injection_in_the_middle():
    words = ["benign"] * 2000
    words[1000] = "INJECT"
    text = " ".join(words)
    clf, session = make_clf()
    (res,) = clf.score_detailed([text])
    assert res.windows > 1 and res.windows_scored == res.windows
    assert res.score > 0.99
    start, end = res.span
    assert "INJECT" in text[start:end]
    # every window fits the model limit
    for batch in session.batches:
        assert batch.shape[1] <= 512


def test_injection_cut_at_window_boundary_is_seen_whole():
    # Two-token marker cannot be checked by the stub, but a token at any boundary position must land
    # in at least one window: check every position around the first boundary.
    for pos in range(440, 520):
        words = ["benign"] * 1200
        words[pos] = "INJECT"
        clf, _ = make_clf()
        assert clf.score([" ".join(words)])[0] > 0.99, pos


def test_all_windows_of_all_texts_are_batched_together():
    clf, session = make_clf(max_batch=16, max_batch_tokens=10**9)
    texts = [" ".join(["w"] * 1500), "short one", "INJECT", " ".join(["w"] * 600)]
    scores = clf.score(texts)
    assert [s > 0.5 for s in scores] == [False, False, True, False]
    total_rows = sum(b.shape[0] for b in session.batches)
    assert total_rows == 4 + 1 + 1 + 2
    assert len(session.batches) == 1


def test_window_cap_is_reported():
    clf, _ = make_clf(max_windows_per_text=4)
    (res,) = clf.score_detailed([" ".join(["w"] * 10_000)])
    assert res.windows > 4 and res.windows_scored == 4


def test_concurrent_calls_are_safe():
    clf, _ = make_clf()
    results = {}

    def worker(i):
        text = "INJECT here" if i % 2 else "nothing here"
        results[i] = clf.score([text] * 5)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for i, scores in results.items():
        assert all((s > 0.5) == bool(i % 2) for s in scores)


def test_missing_model_raises_clear_error(tmp_path):
    clf = OnnxInjectionClassifier(model_path=tmp_path)
    with pytest.raises(FileNotFoundError, match="T1 model not found"):
        clf.score(["hello"])
