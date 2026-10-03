"""Cheap language heuristic for routing text to the right semantic layer.

The T1 classifier (protectai/deberta-v3-base-prompt-injection-v2) is trained on English only, so
non-English text is escalated to the T2 judge (policy: prompt_injection.escalate_non_english).
This module answers one question fast and without extra dependencies: "is this text English
enough for T1 to be meaningful?"

Design rules:
- Short texts, code, numbers, URLs, e-mail addresses, file paths and identifiers are neutral and
  count as English: they carry no language signal and must not trigger T2 calls.
- A text is non-English only on positive evidence: a non-Latin script majority, or function words
  (and diacritics) of another language outnumbering English function words.
- Mixed documents are checked per segment, so a Polish or German paragraph hidden inside an
  English web page or tool result is still detected. Names and addresses with diacritics alone
  ("Lukasz Wojcik, ul. Marszalkowska") do not count: a segment needs function words too.

Everything is deterministic; the word lists below are the whole model.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Minimum number of words (after stripping code, URLs, numbers) before we trust any signal
# other than the script. Below this the text is treated as neutral (English).
MIN_WORDS = 4
# Words per segment when a long text is checked piece by piece.
SEGMENT_WORDS = 12
# A segment (or the whole text) needs at least this many foreign function-word hits.
MIN_FOREIGN_HITS = 2

# Function words. Words that are frequent in English too ("a", "i", "to", "do", "na" etc.)
# are deliberately left out of the foreign lists so English text never scores as foreign.
EN_WORDS = frozenset(
    """the and of is are was were be been being that this these those it its for with on as at
    from by an have has had not no what which who whom whose when where why how can could would
    should will shall may might must you your yours we our ours they them their he she his her
    there here about into over under after before please if then than but or any all some each
    every other only also just more most very such so do does did done me my mine us
    i'm it's don't can't isn't aren't won't let's""".split()
)

PL_WORDS = frozenset(
    """się nie jest są być był była było byli jak że czy ale lub albo oraz dla przez przy nad
    jego jej ich nam wam mnie mi cię tego tej temu tym tych te który która które którzy już
    jeszcze tylko bardzo może można proszę wszystkie wszystko wszystkich swoje swój twoje twój
    twoich mój moje moich nasz nasze naszych wasz jakie jaki jaka jakich gdzie kiedy dlaczego
    teraz potem przed od za ze bez aby żeby jeśli jezeli jeżeli również także więc wiec bo tak
    niech zawsze nigdy jako poprzednie poprzednich wcześniejsze wczesniejsze polecenia poleceń
    instrukcje instrukcji zignoruj zapomnij pokaż pokaz wyślij wyslij podaj napisz sie
    w z""".split()
)

DE_WORDS = frozenset(
    """der die das und ist nicht ich du sie es ein eine einen einem einer mit auf für fur von zu
    den dem des auch sich wie wir ihr bitte alle alles vorherigen anweisungen ignoriere vergiss
    sind werden wird kann können oder aber wenn dass daß noch nur schon sehr jetzt dann hier bei
    nach aus über uber unter zwischen durch gegen ohne dein deine ihre unsere mein meine diese
    dieser dieses jede jeder kein keine nichts etwas habe hast haben sein gib zeige schreibe
    sende welche welcher welches wer wo warum heute gibt geht""".split()
)

# Other common Latin-script languages, so they are recognized as "not English" too.
OTHER_WORDS = {
    "fr": frozenset("le la les des une est et que qui dans pour pas sur avec ce cette vous nous ils sont".split()),
    "es": frozenset("el los las una es y que en por para con del se su sus pero como más está".split()),
    "it": frozenset("il lo gli una è che di con del della sono più questo questa".split()),
    "nl": frozenset("het een en van ik je niet dat voor zijn aan ook maar wat deze".split()),
    "pt": frozenset("os uma é que em para com não da se mais como está são".split()),
}

PL_DIACRITICS = set("ąćęłńśźżĄĆĘŁŃŚŹŻ")  # "ó" is shared with other languages, left out
DE_DIACRITICS = set("äöüßÄÖÜ")
# Letter clusters and endings that are common in Polish and rare in English (words of 5+ letters).
_PL_CLUSTERS = re.compile(r"rz|szcz|cz|sz|dz|ść|ych|ymi")
_PL_ENDINGS = ("ów", "ego", "owanie", "anie", "enie", "ania", "enia", "ości", "ość", "owa", "owy", "owych")

_FENCED_CODE = re.compile(r"```.*?(```|$)", re.DOTALL)
_INLINE_CODE = re.compile(r"`[^`\n]*`")
_URL = re.compile(r"\b(?:[a-z][a-z0-9+.-]*://|www\.)\S+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
# Tokens that look like paths, file names, dotted or snake_case identifiers, hex, numbers.
_TECH_TOKEN = re.compile(r"\S*[/\\_=<>{}\[\]|$#@]\S*|\S+\.\S+|\b0x[0-9a-f]+\b|\S*\d\S*", re.IGNORECASE)
_WORD = re.compile(r"[^\W\d_]+(?:'[^\W\d_]+)?", re.UNICODE)
_SEGMENT_SPLIT = re.compile(r"(?<=[.!?;:])\s+|\n+")
# A line where symbols dominate letters is treated as code and dropped.
_CODE_SYMBOLS = set("{}()[];=<>+*/\\|&^%$#@~`\"'")


@dataclass(frozen=True)
class LangGuess:
    """Result of the heuristic.

    lang: "en", "pl", "de", "fr", "es", "it", "nl", "pt", "cyrillic", "cjk", "arabic",
          "greek", "hebrew", "other_script", or "neutral" (too little signal, treated as English).
    english: True when T1 can be trusted on this text.
    reason: short human-readable explanation, safe to put in an audit trace.
    """

    lang: str
    english: bool
    reason: str


def _strip_non_language(text: str) -> str:
    text = _FENCED_CODE.sub(" ", text)
    text = _INLINE_CODE.sub(" ", text)
    text = _URL.sub(" ", text)
    text = _EMAIL.sub(" ", text)
    kept_lines = []
    for line in text.splitlines():
        letters = sum(ch.isalpha() for ch in line)
        symbols = sum(ch in _CODE_SYMBOLS for ch in line)
        if letters and symbols / (letters + symbols) > 0.25:
            continue  # code-like line
        kept_lines.append(line)
    text = "\n".join(kept_lines)
    return _TECH_TOKEN.sub(" ", text)


def _script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "other_script"
    if name.startswith("LATIN"):
        return "latin"
    if name.startswith("CYRILLIC"):
        return "cyrillic"
    if name.startswith(("CJK", "HIRAGANA", "KATAKANA", "HANGUL")):
        return "cjk"
    if name.startswith("ARABIC"):
        return "arabic"
    if name.startswith("GREEK"):
        return "greek"
    if name.startswith("HEBREW"):
        return "hebrew"
    return "other_script"


def _word_script(word: str) -> str:
    """Script of a word by majority of its letters (a Latin word with one Cyrillic homoglyph stays Latin)."""
    counts: dict[str, int] = {}
    for ch in word:
        s = _script_of(ch)
        counts[s] = counts.get(s, 0) + 1
    return max(counts.items(), key=lambda kv: kv[1])[0]


def _is_pl_marked(word: str) -> bool:
    """Polish diacritics or letter clusters that are rare in English (rz, sz, cz, ...)."""
    if any(ch in PL_DIACRITICS for ch in word):
        return True
    w = word.lower()
    return len(w) >= 5 and (_PL_CLUSTERS.search(w) is not None or w.endswith(_PL_ENDINGS))


def _evidence(words: list[str]) -> dict[str, tuple[int, int]]:
    """Per language: (function-word hits, marked words). English has no marked words."""
    hits = {"en": 0, "pl": 0, "de": 0, **{k: 0 for k in OTHER_WORDS}}
    marked = {k: 0 for k in hits}
    for raw in words:
        w = raw.lower()
        if w in EN_WORDS:
            hits["en"] += 1
        if w in PL_WORDS:
            hits["pl"] += 1
        if w in DE_WORDS:
            hits["de"] += 1
        for code, vocab in OTHER_WORDS.items():
            if w in vocab:
                hits[code] += 1
        if _is_pl_marked(raw):
            marked["pl"] += 1
        if any(ch in DE_DIACRITICS for ch in raw):
            marked["de"] += 1
    return {k: (hits[k], marked[k]) for k in hits}


def _foreign_verdict(words: list[str]) -> tuple[str, float, int] | None:
    """Return (lang, foreign_score, english_hits) if these words are confidently not English.

    A language needs function-word evidence: at least MIN_FOREIGN_HITS function words, or one
    function word plus two marked words (diacritics, typical clusters). Marked words alone never
    decide, because customer names and street names carry diacritics in any language.
    Marked words add half a point to the score that is compared with English hits.
    """
    ev = _evidence(words)
    en_hits = ev.pop("en")[0]
    best: tuple[str, float, int] | None = None
    for lang, (hits, marked) in ev.items():
        if not (hits >= MIN_FOREIGN_HITS or (hits >= 1 and marked >= 2)):
            continue
        score = hits + 0.5 * marked
        if score > en_hits and (best is None or score > best[1]):
            best = (lang, score, en_hits)
    return best


def detect_language(text: str) -> LangGuess:
    """Classify `text` as English (or neutral) vs another language. See module docstring."""
    if not text or not text.strip():
        return LangGuess("neutral", True, "empty")
    cleaned = _strip_non_language(text)
    words = _WORD.findall(cleaned)
    if not words:
        return LangGuess("neutral", True, "no natural-language words (code, numbers or URLs only)")

    # 1. Script: a majority of non-Latin words means not English, even for short texts.
    script_counts: dict[str, int] = {}
    for w in words:
        s = _word_script(w)
        script_counts[s] = script_counts.get(s, 0) + 1
    non_latin = {k: v for k, v in script_counts.items() if k != "latin"}
    if non_latin:
        top_script, top_n = max(non_latin.items(), key=lambda kv: kv[1])
        if top_n / len(words) > 0.5:
            return LangGuess(top_script, False, f"{top_n}/{len(words)} words in {top_script} script")
        # A substantial non-Latin passage inside a Latin text (e.g. a Russian paragraph).
        if top_n >= SEGMENT_WORDS:
            return LangGuess(top_script, False, f"{top_n} words in {top_script} script inside the text")

    latin_words = [w for w in words if _word_script(w) == "latin"]
    if len(latin_words) < MIN_WORDS:
        return LangGuess("neutral", True, f"only {len(latin_words)} words, too short to judge")

    # 2. Whole text.
    verdict = _foreign_verdict(latin_words)
    if verdict:
        lang, best, en = verdict
        return LangGuess(lang, False, f"{lang} evidence outweighs English ({best:g} vs {en} function words)")

    # 3. Segments: catch a foreign paragraph hidden in a mostly English document.
    if len(latin_words) > SEGMENT_WORDS:
        for segment in _segments(cleaned):
            seg_words = [w for w in _WORD.findall(segment) if _word_script(w) == "latin"]
            if len(seg_words) < MIN_WORDS:
                continue
            verdict = _foreign_verdict(seg_words)
            if verdict:
                lang, best, en = verdict
                return LangGuess(lang, False, f"a {lang} passage inside the text ({best:g} vs {en} English)")

    en_hits = _evidence(latin_words)["en"][0]
    if en_hits == 0:
        # No English function words and no other language recognized: keyword queries, lists of
        # names, or an unknown Latin-script language. Neutral (T1 still runs), but say so.
        return LangGuess("neutral", True, "no function words of any known language")
    return LangGuess("en", True, f"English function words: {en_hits}")


def _segments(text: str) -> list[str]:
    """Split into sentence-like pieces, then merge short pieces up to about SEGMENT_WORDS words."""
    pieces = [p for p in _SEGMENT_SPLIT.split(text) if p and p.strip()]
    merged: list[str] = []
    buf: list[str] = []
    count = 0
    for p in pieces:
        n = len(_WORD.findall(p))
        buf.append(p)
        count += n
        if count >= SEGMENT_WORDS:
            merged.append(" ".join(buf))
            buf, count = [], 0
    if buf:
        merged.append(" ".join(buf))
    return merged


def is_probably_english(text: str) -> bool:
    """True when T1 (English-only) can be trusted on `text`; False means escalate to T2."""
    return detect_language(text).english
