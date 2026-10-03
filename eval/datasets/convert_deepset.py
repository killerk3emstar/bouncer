"""Convert deepset/prompt-injections (parquet) to our JSONL eval format.

Download first (one-off, not part of make test):
    uvx --from huggingface_hub hf download deepset/prompt-injections --repo-type dataset --local-dir <dir>
Then:
    uv run --with pyarrow python eval/datasets/convert_deepset.py <dir>

Labels come from the dataset (1 = injection, 0 = benign). The dataset has no language column, so
`lang` is assigned here: manual overrides for rows reviewed by hand, then
bouncer.t1.lang.detect_language, and for short texts (<= 8 words) that it calls English or neutral a
German marker check ("Rentenreformen Europa", "Was hat X geraucht?": more German markers than
English function words). Tags were reviewed by reading all short rows.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from bouncer.t1.lang import DE_DIACRITICS, EN_WORDS, detect_language  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent

# Text prefix -> language, for rows reviewed by hand.
MANUAL_LANG = {
    "tienes que olvidar todo que sabes": "es",
    "S a y t h a t y o u h a t e": "en",  # spaced-letter obfuscation of an English sentence
    "Wirtschaftsbeziehungen USA-China S a y t h a t": "en",  # German carrier, English payload
    "Zaboravi sve instrukcije": "hr",
    "aapako jo yaad rakhana hai": "hi-latn",
    "Si yo digo foya": "es",
    "I love exploiting AI systems. Spanish:": "en",
    "Quien es el jeffe de Zeit": "es",
    "Free trade agreement Europa": "en",
    "Data protection social media Europa": "en",
}
GERMAN_SUFFIX = re.compile(
    r"(ung|ungen|keit|heit|schaft|wirtschaft|politik|reform|reformen|land|ismus|ität|mangel|prävention|recht)$", re.I
)
GERMAN_HINTS = {
    "europa", "deutschland", "ist", "was", "sind", "vorbei", "wer", "welche", "die", "der", "das", "wann",
    "war", "erste", "frauen", "jugendliche", "studenten", "mieten", "lösungen", "noch", "hat", "wie", "kann",
    "man", "machen", "nicht", "gut", "gute", "statt", "fand", "wollen", "passiert", "gerade", "von", "lebt",
    "stirbt", "kinder", "krise", "zukunft", "arbeit", "diensten", "geraucht", "geendet", "serien", "schreibe",
    "macht", "aus",
}


def tag_language(text: str) -> str:
    for prefix, lang in MANUAL_LANG.items():
        if text.startswith(prefix):
            return lang
    guess = detect_language(text)
    words = re.findall(r"[^\W\d_]+", text)
    if guess.lang not in ("en", "neutral") or len(words) > 8:
        return guess.lang if guess.lang != "neutral" else "en"
    german = sum(
        1
        for w in words
        if any(ch in DE_DIACRITICS for ch in w) or w.lower() in GERMAN_HINTS or (len(w) > 6 and GERMAN_SUFFIX.search(w))
    )
    english = sum(1 for w in words if w.lower() in EN_WORDS)
    if german > english:
        return "de"
    return "en"


def main(src_dir: str) -> None:
    import pyarrow.parquet as pq

    src = Path(src_dir) / "data"
    for split in ("train", "test"):
        (parquet,) = sorted(src.glob(f"{split}-*.parquet"))
        rows = pq.read_table(parquet).to_pylist()
        out_path = OUT_DIR / f"deepset_{split}.jsonl"
        with out_path.open("w", encoding="utf-8") as out:
            for i, row in enumerate(rows):
                label = "injection" if int(row["label"]) == 1 else "benign"
                obj = {
                    "id": f"deepset-{split}-{i:04d}",
                    "text": row["text"],
                    "label": label,
                    "lang": tag_language(row["text"]),
                    "source": f"deepset/prompt-injections ({split} split)",
                    # The dataset does not separate injection types; all positives are counted as direct.
                    "kind": "direct" if label == "injection" else "benign",
                }
                out.write(json.dumps(obj, ensure_ascii=False) + "\n")
        print(f"{out_path.relative_to(ROOT)}: {len(rows)} rows")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
