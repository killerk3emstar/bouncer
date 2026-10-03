"""T1 layer: prompt-injection classifier and the language check that decides when T1 applies.

Gateway usage:

    from bouncer.t1 import get_classifier, is_probably_english

    clf = get_classifier()            # env T1_BACKEND=onnx (default) | fake; load once
    clf.load()                        # optional eager load + warm-up at start-up (ONNX only)
    scores = await asyncio.to_thread(clf.score, fragments)   # list[float] in [0, 1]
    route_to_t2 = not is_probably_english(fragment)

The ONNX classifier also has `score_detailed(texts) -> list[T1Result]` with the character span of
the highest-scoring window, for the finding span in the audit trace.
"""

from bouncer.t1.classifier import (
    InjectionClassifier,
    OnnxInjectionClassifier,
    T1Result,
    get_classifier,
    load_classifier,
)
from bouncer.t1.fake import FakeInjectionClassifier
from bouncer.t1.lang import LangGuess, detect_language, is_probably_english

__all__ = [
    "FakeInjectionClassifier",
    "InjectionClassifier",
    "LangGuess",
    "OnnxInjectionClassifier",
    "T1Result",
    "detect_language",
    "get_classifier",
    "is_probably_english",
    "load_classifier",
]
