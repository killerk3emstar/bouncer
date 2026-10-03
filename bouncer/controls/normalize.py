"""Normalization and obfuscation detection (control id "obfuscation").

prepare() turns one Segment into:
  clean_text  the text the gateway forwards (invisible characters, bidi controls and Unicode tag
              characters removed when strip_invisible is on),
  views       [raw, normalized, (normalized:case), decoded:*] copies that every text control scans,
  findings    obfuscation findings (ASCII smuggling, invisible characters, homoglyphs, encoded blobs).

Views:
  raw              clean_text itself; offsets are exact.
  normalized       NFKC, homoglyphs folded to Latin, diacritics stripped, casefolded, leetspeak folded,
                   spaced-out letters joined ("i g n o r e" -> "ignore"), whitespace collapsed (newlines
                   kept), string concatenations joined. For phrase matching (prompt injection).
  normalized:case  NFKC, homoglyphs folded, string concatenations joined, case and digits preserved.
                   Only present when it differs from raw. For secrets split or disguised with lookalikes.
  decoded:<enc>    a base64 / hex / url-encoded blob found in the raw text, decoded (recursively up to
                   max_decode_depth). span = [start, end) of the blob in clean_text.
  decoded:rot13 / decoded:reversed
                   the whole text, only when the transformed text reads clearly more like English.
  decoded:unicode-tags / decoded:variation-selectors
                   hidden ASCII carried by invisible characters (ASCII smuggling).

Other controls decide whether decoded content is malicious; this module only reports that it exists.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from urllib.parse import unquote_plus

from bouncer.core import Action, Finding, Segment, View, mask
from bouncer.policy.schema import ObfuscationCfg

CONTROL_ID = "obfuscation"
OWASP_LLM = ["LLM01"]
OWASP_AGENTIC = ["ASI01"]
ATLAS = ["AML.T0068"]  # LLM Prompt Obfuscation (verified in mitre-atlas/atlas-data dist/ATLAS.yaml)

MAX_SCAN_CHARS = 200_000  # decoding and heuristics look at most at this many characters
MAX_DECODED_VIEWS = 16
MAX_BLOB_CHARS = 65_536
MAX_DECODED_CHARS = 20_000
MIN_BLOB_CHARS = 16

# --------------------------------------------------------------------------- invisible characters

_ZERO_WIDTH = set(range(0x200B, 0x2010)) | set(range(0x2060, 0x2065)) | {0xFEFF, 0x00AD, 0x180E, 0x061C}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_SPECIAL_RE = re.compile(
    "[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\ufe00-\ufe0f"
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef]+"
)
# England / Scotland / Wales flags: U+1F3F4 + tag letters + U+E007F cancel tag. Legitimate, keep.
_FLAG_RE = re.compile("\U0001f3f4[\U000e0030-\U000e0039\U000e0061-\U000e007a]{2,6}\U000e007f")
_CF_RE = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f"
    "\u3164\ufe00-\ufe0f\ufeff\uffa0\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)


def _is_tag(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def _is_vs(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def _emojiish(ch: str) -> bool:
    if not ch:
        return False
    cp = ord(ch)
    return cp >= 0x1F000 or 0x2190 <= cp <= 0x2BFF or cp == 0x20E3 or (cp > 0x7F and unicodedata.category(ch) == "So")


def _vs_byte(cp: int) -> int | None:
    """Variation selector to byte value (the encoding used for 'emoji smuggling')."""
    if 0xFE00 <= cp <= 0xFE0F:
        return cp - 0xFE00
    if 0xE0100 <= cp <= 0xE01EF:
        return cp - 0xE0100 + 16
    return None


class _InvisibleReport:
    __slots__ = ("counts", "tag_runs", "vs_payloads", "inside_word", "leading_bom")

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.tag_runs: list[tuple[int, int, str]] = []  # (start, end) in original text, hidden ascii
        self.vs_payloads: list[str] = []
        self.inside_word = False
        self.leading_bom = False


def _strip_invisible(text: str, strip: bool) -> tuple[str, _InvisibleReport]:
    """Remove invisible characters (or keep them when strip=False) and report what was there."""
    rep = _InvisibleReport()
    if text.isascii():
        return text, rep
    keep_ranges = [(m.start(), m.end()) for m in _FLAG_RE.finditer(text)]

    def in_flag(pos: int) -> bool:
        return any(s <= pos < e for s, e in keep_ranges)

    out: list[str] = []
    last = 0
    for m in _SPECIAL_RE.finditer(text):
        s, e = m.start(), m.end()
        if in_flag(s):
            continue
        run = m.group()
        prev_ch = text[s - 1] if s > 0 else ""
        next_ch = text[e] if e < len(text) else ""
        cps = [ord(c) for c in run]
        # Legitimate joiners: emoji ZWJ sequences, emoji presentation selectors, keycaps, ZWNJ/ZWJ in
        # non-Latin scripts. Short runs of only these characters between such neighbours stay.
        if len(cps) <= 3 and all(cp in (0x200C, 0x200D, 0xFE0E, 0xFE0F) for cp in cps):
            if _emojiish(prev_ch) or _emojiish(next_ch) or (prev_ch and not prev_ch.isascii() and next_ch and not next_ch.isascii()):
                continue
            if prev_ch.isdigit() or prev_ch in "#*":
                continue
        if s == 0 and cps == [0xFEFF]:
            rep.leading_bom = True
            out.append(text[last:s])
            last = e
            continue
        tag_cps = [cp for cp in cps if _is_tag(cp)]
        vs_cps = [cp for cp in cps if _is_vs(cp)]
        if tag_cps:
            hidden = "".join(chr(cp - 0xE0000) for cp in tag_cps if 0xE0020 <= cp <= 0xE007E)
            rep.tag_runs.append((s, e, hidden))
            rep.counts["U+E00xx tag"] = rep.counts.get("U+E00xx tag", 0) + len(tag_cps)
        if len(vs_cps) >= 4:
            data = bytes(b for b in (_vs_byte(cp) for cp in vs_cps) if b is not None)
            try:
                decoded = data.decode("utf-8")
            except UnicodeDecodeError:
                decoded = ""
            if decoded and _printable_ratio(decoded) >= 0.85:
                rep.vs_payloads.append(decoded)
            rep.counts["variation selector"] = rep.counts.get("variation selector", 0) + len(vs_cps)
        elif vs_cps and not (prev_ch.isascii() and prev_ch.isalpha()) and len(vs_cps) == len(cps) and len(vs_cps) <= 1:
            continue  # a single variation selector after a symbol: emoji presentation, keep
        for cp in cps:
            if _is_tag(cp) or _is_vs(cp):
                continue
            key = f"U+{cp:04X}"
            rep.counts[key] = rep.counts.get(key, 0) + 1
        if prev_ch.isalnum() and next_ch.isalnum():
            rep.inside_word = True
        if strip:
            out.append(text[last:s])
            last = e
    if not strip:
        return text, rep
    out.append(text[last:])
    return "".join(out), rep


# --------------------------------------------------------------------------- homoglyphs

_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c",
    "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l",
    "ԛ": "q", "ԝ": "w", "ү": "y", "ɡ": "g",
    "А": "A", "В": "B", "Е": "E", "Ё": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S", "І": "I", "Ї": "I", "Ј": "J", "Һ": "H", "Ӏ": "I", "Ԛ": "Q",
    "Ԝ": "W", "Ү": "Y",
    # Greek
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "χ": "x", "ε": "e",
    "ϲ": "c", "ϳ": "j", "η": "n", "ω": "w", "γ": "y",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "Ϲ": "C",
    # Armenian
    "օ": "o", "ս": "u", "ց": "g", "հ": "h",
    # Latin lookalikes outside ASCII (dotless i, script a/g, small capitals)
    "ı": "i", "ɑ": "a", "ɩ": "i", "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ɢ": "g", "ʜ": "h",
    "ɪ": "i", "ᴊ": "j", "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ʀ": "r", "ꜱ": "s",
    "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)
# letters without a decomposition that should still fold to ASCII
_EXTRA_FOLD = str.maketrans({"ł": "l", "Ł": "L", "đ": "d", "Đ": "D", "ø": "o", "Ø": "O", "ħ": "h", "ŀ": "l", "ß": "ss"})
_WORD_RE = re.compile(r"[^\W\d_]+")


def _strip_marks(text: str) -> str:
    if text.isascii():
        return text
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return unicodedata.normalize("NFC", stripped).translate(_EXTRA_FOLD)


def _fold_homoglyphs(text: str) -> tuple[str, list[str]]:
    """Fold lookalike letters to Latin inside words that are Latin or entirely made of lookalikes.

    Real Cyrillic or Greek words (which contain letters with no Latin twin) are left alone.
    Returns (folded text, list of mixed-script words as they appeared).
    """
    if text.isascii():
        return text, []
    mixed: list[str] = []

    def fold(m: re.Match[str]) -> str:
        w = m.group()
        if w.isascii():
            return w
        has_conf = any(c in _CONFUSABLES for c in w)
        if not has_conf:
            return w
        has_ascii = any(c.isascii() for c in w)
        all_conf = all(c.isascii() or c in _CONFUSABLES for c in w)
        if has_ascii and all_conf:
            mixed.append(w)
            return w.translate(_CONFUSABLE_TABLE)
        if all_conf and len(w) >= 2:
            return w.translate(_CONFUSABLE_TABLE)
        return w

    return _WORD_RE.sub(fold, text), mixed


# --------------------------------------------------------------------------- normalized view

_LEET_TABLE = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_LEET_TOKEN_RE = re.compile(r"[a-z0-9@$]*[0-9@$][a-z0-9@$]*")
_BANG_RE = re.compile(r"!(?=[a-z])")
_SPACED_RE = re.compile(r"(?<![^\W_])[^\W_](?P<sep>[ .\-_*·•|/\n])(?:[^\W_](?P=sep)){1,}[^\W_](?![^\W_])")
_SPACED_SEP_RE = re.compile(r"[ .\-_*·•|/\n]")
_HSPACE_RE = re.compile(r"[^\S\n]+")
_VSPACE_RE = re.compile(r"\s*\n\s*")
_CONCAT_RE = re.compile(r"""(?<=[\w/+=-])["'`]\s*(?:\+|\.|\|\||&|,\s*\+)?\s*["'`](?=[\w/+=-])""")


def _leet(text: str) -> str:
    text = _BANG_RE.sub("i", text)

    def fold(m: re.Match[str]) -> str:
        tok = m.group()
        if any(c.isalpha() for c in tok):
            return tok.translate(_LEET_TABLE)
        return tok

    return _LEET_TOKEN_RE.sub(fold, text)


def _collapse_spaced(text: str) -> str:
    return _SPACED_RE.sub(lambda m: _SPACED_SEP_RE.sub("", m.group()), text)


def join_concatenations(text: str) -> str:
    """'"AKIA" + "IOSF..."' -> '"AKIAIOSF..."' (also implicit and PHP/SQL concatenation)."""
    if "'" not in text and '"' not in text and "`" not in text:
        return text
    return _CONCAT_RE.sub("", text)


def fold_case_preserving(text: str, homoglyphs: bool = True) -> tuple[str, list[str]]:
    """NFKC + invisible characters removed + homoglyphs folded (case, digits and diacritics kept)."""
    if text.isascii():
        return text, []
    t = unicodedata.normalize("NFKC", text)
    t = _CF_RE.sub("", t)
    if not homoglyphs:
        return t, []
    return _fold_homoglyphs(t)


def normalize_text(text: str, homoglyphs: bool = True) -> str:
    """The 'normalized' view: lowercase, lookalikes and leetspeak folded, spaced letters joined."""
    t, _ = fold_case_preserving(text, homoglyphs)
    t = join_concatenations(t)
    t = t.casefold()
    if not t.isascii():
        t = _strip_marks(t)
    t = _leet(t)
    t = _collapse_spaced(t)
    t = _HSPACE_RE.sub(" ", t)
    t = _VSPACE_RE.sub("\n", t)
    return t.strip()


# --------------------------------------------------------------------------- decoding

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}(?:\r?\n[A-Za-z0-9+/_-]{4,})*={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_PLAIN_RE = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Za-z])")
_HEX_SEP_RE = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}[ :]){7,}[0-9A-Fa-f]{2}(?![0-9A-Za-z])")
_HEX_ESC_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}")
_HEX_0X_RE = re.compile(r"(?:0x[0-9A-Fa-f]{2}(?:\s*,\s*|\s+)?){4,}")
_UNI_ESC_RE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}){4,}")
_ENTITY_RE = re.compile(r"(?:&#(?:x[0-9A-Fa-f]{1,6}|\d{1,7});){4,}")
_URL_ENC_RE = re.compile(r"[^\s\"'<>()\[\]]*%[0-9A-Fa-f]{2}[^\s\"'<>()\[\]]*")
_PCT_RE = re.compile(r"%([0-9A-Fa-f]{2})")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return ok / len(s)


def _looks_textual(s: str) -> bool:
    if len(s) < 6 or _printable_ratio(s) < 0.9:
        return False
    letters = sum(1 for c in s if c.isalpha())
    return letters >= 4 and letters / len(s) >= 0.3


def _b64_decode(blob: str) -> str | None:
    s = re.sub(r"\s+", "", blob).rstrip("=")
    if "-" in s or "_" in s:
        if "+" in s or "/" in s:
            return None
        s = s.replace("-", "+").replace("_", "/")
    if len(s) % 4 == 1:
        return None
    s += "=" * (-len(s) % 4)
    try:
        head = base64.b64decode(s[:64] + "=" * (-len(s[:64]) % 4) if len(s) > 64 else s, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        head_txt = head.decode("utf-8", errors="ignore")
    except Exception:  # pragma: no cover
        return None
    if _printable_ratio(head_txt) < 0.85 or len(head_txt) < len(head) * 0.6:
        return None
    try:
        raw = base64.b64decode(s, validate=True)
        txt = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return txt if _looks_textual(txt) else None


def _hex_decode(blob: str) -> str | None:
    digits = re.sub(r"\\x|0x|[\s:,]", "", blob)
    if len(digits) % 2:
        return None
    try:
        txt = bytes.fromhex(digits).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return txt if _looks_textual(txt) else None


def _uni_decode(blob: str) -> str | None:
    try:
        txt = re.sub(r"\\u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), blob)
    except ValueError:
        return None
    return txt if _looks_textual(txt) else None


def _entity_decode(blob: str) -> str | None:
    txt = html.unescape(blob)
    return txt if _looks_textual(txt) else None


def _url_decode(blob: str) -> tuple[str, bool] | None:
    escapes = _PCT_RE.findall(blob)
    if len(escapes) < 3:
        return None
    txt = unquote_plus(blob)
    if txt == blob or not _looks_textual(txt):
        return None
    # Encoding letters or digits is never needed in a URL, so it signals deliberate obfuscation.
    unreserved = sum(1 for h in escapes if chr(int(h, 16)).isalnum())
    suspicious = unreserved >= 3 or len(escapes) * 3 >= len(blob) * 0.5
    return txt, suspicious


def _find_blobs(text: str, encodings: list[str]) -> list[tuple[int, int, str, str, bool]]:
    """Return (start, end, encoding, decoded, suspicious) for encoded blobs in text."""
    found: list[tuple[int, int, str, str, bool]] = []
    taken: list[tuple[int, int]] = []

    def free(s: int, e: int) -> bool:
        return all(e <= ts or s >= te for ts, te in taken)

    def add(s: int, e: int, enc: str, dec: str, sus: bool = True) -> None:
        found.append((s, e, enc, dec[:MAX_DECODED_CHARS], sus))
        taken.append((s, e))

    if "hex" in encodings:
        for rx, fn, hint in ((_HEX_ESC_RE, _hex_decode, "\\x"), (_HEX_0X_RE, _hex_decode, "0x"),
                             (_UNI_ESC_RE, _uni_decode, "\\u"), (_ENTITY_RE, _entity_decode, "&#"),
                             (_HEX_SEP_RE, _hex_decode, None), (_HEX_PLAIN_RE, _hex_decode, None)):
            if hint is not None and hint not in text:
                continue
            for m in rx.finditer(text):
                if len(found) >= MAX_DECODED_VIEWS:
                    return found
                if m.end() - m.start() > MAX_BLOB_CHARS or not free(m.start(), m.end()):
                    continue
                dec = fn(m.group())
                if dec:
                    add(m.start(), m.end(), "hex", dec)
    if "base64" in encodings:
        n = 0
        for m in _B64_RE.finditer(text):
            n += 1
            if n > 64 or len(found) >= MAX_DECODED_VIEWS:
                break
            blob = m.group()
            if len(blob) > MAX_BLOB_CHARS or not free(m.start(), m.end()):
                continue
            if blob.isalpha() and blob.islower():
                continue  # one long lowercase word
            dec = _b64_decode(blob)
            if dec:
                add(m.start(), m.end(), "base64", dec)
    if "url" in encodings and "%" in text and _PCT_RE.search(text):
        for m in _URL_ENC_RE.finditer(text):
            if len(found) >= MAX_DECODED_VIEWS:
                break
            if m.end() - m.start() > MAX_BLOB_CHARS or not free(m.start(), m.end()):
                continue
            r = _url_decode(m.group())
            if r:
                add(m.start(), m.end(), "url", r[0], r[1])
    return found


# --------------------------------------------------------------------------- rot13 / reversed

_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
_STOPWORDS = frozenset(
    "the and you your all to of is are that this for with not be now from what any ignore instructions "
    "previous prior system prompt reveal password secret tell me print show above rules".split()
)
_ASCII_WORD_RE = re.compile(r"[A-Za-z]+")
_ROT_HINT_RE = re.compile(r"\brot[\s_-]?13\b", re.I)


def _rot_and_reverse_views(text: str) -> list[View]:
    """Add ROT13 / reversed copies when they read clearly more like English than the text itself."""
    views: list[View] = []
    if len(text) > 20_000:
        return views
    words = [w.lower() for w in _ASCII_WORD_RE.findall(text[:4000])]
    if not words:
        return views
    base = sum(1 for w in words if w in _STOPWORDS)

    def reads_english(transformed: list[str]) -> bool:
        hits = [w for w in transformed if w in _STOPWORDS]
        # enough stopwords, more than the original, a real share of the text, and not one repeated token ("gb" -> "to")
        return len(hits) >= 3 and len(hits) > 2 * base and len(hits) >= 0.08 * len(words) and len(set(hits)) >= 2

    if _ROT_HINT_RE.search(text) or reads_english([w.translate(_ROT13) for w in words]):
        views.append(View(text.translate(_ROT13), "decoded:rot13", (0, len(text))))
    if reads_english([w[::-1] for w in words]):
        views.append(View(text[::-1], "decoded:reversed", (0, len(text))))
    return views


# --------------------------------------------------------------------------- findings


def _finding(rule: str, action: Action, severity: str, message: str, **kw: object) -> Finding:
    return Finding(
        control=CONTROL_ID,
        rule=rule,
        severity=severity,  # type: ignore[arg-type]
        action=action,
        message=message,
        owasp_llm=list(OWASP_LLM),
        owasp_agentic=list(OWASP_AGENTIC),
        atlas=list(ATLAS),
        **kw,  # type: ignore[arg-type]
    )


def _snippet(s: str, n: int = 60) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."


def prepare(segment: Segment, cfg: ObfuscationCfg | None) -> tuple[str, list[View], list[Finding]]:
    """Normalize a segment: clean text to forward, views to scan, obfuscation findings."""
    text = segment.text or ""
    if cfg is None:
        return text, [View(text, "raw")], []

    findings: list[Finding] = []
    clean, rep = _strip_invisible(text, cfg.strip_invisible)
    views: list[View] = [View(clean, "raw")]
    scan_text = clean[:MAX_SCAN_CHARS]

    # Unicode tag characters: invisible ASCII the model can read (ASCII smuggling).
    if rep.tag_runs:
        hidden = " ".join(h for _, _, h in rep.tag_runs if h)
        tag_action = Action.parse(cfg.unicode_tag_chars)
        count = rep.counts.get("U+E00xx tag", 0)
        for i, (s, e, h) in enumerate(rep.tag_runs[:5]):
            span = (s, e) if not cfg.strip_invisible else None
            if i == 0 or span is not None:
                findings.append(
                    _finding(
                        "unicode-tag-chars",
                        tag_action,
                        "high",
                        f"{count} invisible Unicode tag characters carry hidden text "
                        f"('{_snippet(mask(h, 12, 0) if len(h) > 40 else h, 48)}'). This is ASCII smuggling: the "
                        "model reads instructions the user cannot see. Treat the source as hostile and remove the "
                        "hidden text.",
                        span=span,
                        evidence=_snippet(h, 48),
                    )
                )
        if hidden:
            views.append(View(hidden, "decoded:unicode-tags", None))
    if rep.vs_payloads:
        views.append(View(" ".join(rep.vs_payloads), "decoded:variation-selectors", None))
        findings.append(
            _finding(
                "variation-selector-smuggling",
                Action.parse(cfg.unicode_tag_chars),
                "high",
                f"A run of variation selectors encodes hidden text ('{_snippet(rep.vs_payloads[0], 48)}'). "
                "Data hidden in invisible characters is a smuggling technique; remove it and check the source.",
                evidence=_snippet(rep.vs_payloads[0], 48),
            )
        )
    other = {k: v for k, v in rep.counts.items() if not k.startswith("U+E00xx") and k != "variation selector"}
    if other:
        total = sum(other.values())
        desc = ", ".join(f"{k} x{v}" for k, v in sorted(other.items()))
        verb = "were removed from" if cfg.strip_invisible else "are present in"
        findings.append(
            _finding(
                "invisible-chars",
                Action.LOG,
                "medium" if rep.inside_word else "low",
                f"{total} invisible characters (zero-width or bidi controls: {desc}) {verb} the text. They can split "
                "keywords to evade filters or reorder what a reviewer sees; check where this content came from.",
                evidence=desc,
            )
        )

    # Normalized views.
    case_view, mixed = fold_case_preserving(scan_text, cfg.homoglyphs)
    case_view = join_concatenations(case_view)
    views.append(View(normalize_text(scan_text, cfg.homoglyphs), "normalized", None))
    if case_view != scan_text:
        views.append(View(case_view, "normalized:case", None))
    if mixed:
        sample = ", ".join(sorted({w.translate(_CONFUSABLE_TABLE) for w in mixed})[:5])
        findings.append(
            _finding(
                "mixed-script-homoglyphs",
                Action.LOG,
                "medium",
                f"{len(mixed)} word(s) mix Latin letters with Cyrillic, Greek or other lookalike letters "
                f"(read as: {sample}). Lookalike letters are used to slip blocked words past filters; the text was "
                "scanned in its folded form.",
                evidence=sample,
            )
        )

    # Decoded views (recursively).
    if cfg.decode and cfg.max_decode_depth > 0:
        frontier: list[tuple[str, tuple[int, int] | None, int]] = [(scan_text, None, 1)]
        n_views = 0
        while frontier and n_views < MAX_DECODED_VIEWS:
            src, outer, depth = frontier.pop(0)
            for s, e, enc, dec, suspicious in _find_blobs(src, list(cfg.decode)):
                span = outer if outer is not None else (s, e)
                kind = f"decoded:{enc}"
                views.append(View(dec, kind, span))
                n_views += 1
                if suspicious:
                    findings.append(
                        _finding(
                            "encoded-payload",
                            Action.LOG,
                            "info",
                            f"A {enc}-encoded blob decodes to text ('{_snippet(dec, 40)}'"
                            f"{', nested ' + str(depth) + ' levels' if depth > 1 else ''}). The decoded copy was "
                            "scanned by every text control; encoding is a common way to hide instructions.",
                            span=span,
                            evidence=_snippet(dec, 40),
                            view=kind,
                        )
                    )
                if depth < cfg.max_decode_depth:
                    frontier.append((dec, span, depth + 1))
                if n_views >= MAX_DECODED_VIEWS:
                    break

    for v in _rot_and_reverse_views(scan_text):
        views.append(v)
        findings.append(
            _finding(
                "encoded-payload",
                Action.LOG,
                "info",
                f"The text reads as English after {'ROT13' if v.kind.endswith('rot13') else 'reversing it'} "
                f"('{_snippet(v.text, 40)}'). The transformed copy was scanned by every text control.",
                span=None,
                evidence=_snippet(v.text, 40),
                view=v.kind,
            )
        )
    return clean, views, findings


def view_of(views: list[View], kind: str) -> View | None:
    for v in views:
        if v.kind == kind:
            return v
    return None
