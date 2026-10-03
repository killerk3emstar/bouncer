"""PII detection with validation (control id "pii").

Entities: EMAIL, PHONE, PESEL, NIP, IBAN, CREDIT_CARD. Where a checksum exists it is verified, so a
random number that happens to have the right length is not reported (a PESEL with a wrong checksum is
just a number). Overlaps are resolved by specificity: IBAN > CREDIT_CARD > PESEL > NIP > PHONE.

Scans the raw view (exact spans) and decoded base64/hex/url views (span = the encoded blob).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from bouncer.core import Action, Control, Finding, ScanContext, Segment, View, mask
from bouncer.policy.schema import PiiCfg

MAX_SCAN_CHARS = 200_000
ATLAS = ["AML.T0057"]  # LLM Data Leakage (verified in mitre-atlas/atlas-data)

WHERE = {
    "input": "in the prompt",
    "output": "in the model response",
    "tool_call": "in tool call arguments",
    "tool_result": "in a tool result",
    "tool_definition": "in a tool definition",
}
TITLES = {
    "EMAIL": "Email address",
    "PHONE": "Phone number",
    "PESEL": "PESEL (Polish national ID, checksum valid)",
    "NIP": "NIP (Polish tax ID, checksum valid)",
    "IBAN": "Bank account number (IBAN, mod-97 valid)",
    "CREDIT_CARD": "Payment card number (Luhn valid)",
}
PRIORITY = {"IBAN": 0, "CREDIT_CARD": 1, "PESEL": 2, "NIP": 3, "PHONE": 4, "EMAIL": 5}


@dataclass(frozen=True, slots=True)
class PiiHit:
    entity: str
    start: int
    end: int
    value: str


# --------------------------------------------------------------------------- validators


_NON_DIGIT_RE = re.compile(r"\D+")


def _digits(s: str) -> str:
    if s.isascii():
        return _NON_DIGIT_RE.sub("", s)
    return "".join(str(int(c)) for c in s if c.isdigit())


def pesel_valid(d: str) -> bool:
    if len(d) != 11 or not d.isdigit():
        return False
    w = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    check = (10 - sum(int(a) * b for a, b in zip(d[:10], w, strict=False)) % 10) % 10
    if check != int(d[10]):
        return False
    yy, mm, dd = int(d[0:2]), int(d[2:4]), int(d[4:6])
    century = {0: 1900, 20: 2000, 40: 2100, 60: 2200, 80: 1800}
    base = mm - (mm % 20) if mm % 20 else mm - 20
    month = mm - base
    if base not in century or not 1 <= month <= 12:
        return False
    year = century[base] + yy
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
    return 1 <= dd <= days


def nip_valid(d: str) -> bool:
    if len(d) != 10 or not d.isdigit() or d == "0" * 10:
        return False
    w = (6, 5, 7, 2, 3, 4, 5, 6, 7)
    check = sum(int(a) * b for a, b in zip(d[:9], w, strict=False)) % 11
    return check != 10 and check == int(d[9])


IBAN_LENGTHS = {
    "AD": 24, "AT": 20, "BE": 16, "BG": 22, "CH": 21, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "EE": 20,
    "ES": 24, "FI": 18, "FR": 27, "GB": 22, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IS": 26, "IT": 27,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25,
    "RO": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "UA": 29, "AE": 23, "SA": 24, "TR": 26, "IL": 23,
}


def iban_valid(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if len(s) < 15 or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    exp = IBAN_LENGTHS.get(s[:2])
    if exp is not None and len(s) != exp:
        return False
    if exp is None and not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    try:
        num = "".join(str(int(c, 36)) for c in moved)
    except ValueError:
        return False
    return int(num) % 97 == 1


def luhn_valid(d: str) -> bool:
    total = 0
    for i, c in enumerate(reversed(d)):
        n = int(c)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def card_brand(d: str) -> str | None:
    n = len(d)
    if d[0] == "4" and n in (13, 16, 19):
        return "Visa"
    p2, p4 = int(d[:2]), int(d[:4])
    if (51 <= p2 <= 55 or 2221 <= p4 <= 2720) and n == 16:
        return "Mastercard"
    if p2 in (34, 37) and n == 15:
        return "Amex"
    if (d.startswith("6011") or d.startswith("65") or 644 <= int(d[:3]) <= 649) and 16 <= n <= 19:
        return "Discover"
    if 3528 <= p4 <= 3589 and 16 <= n <= 19:
        return "JCB"
    if (300 <= int(d[:3]) <= 305 or p2 in (36, 38, 39)) and 14 <= n <= 19:
        return "Diners"
    if d.startswith("62") and 16 <= n <= 19:
        return "UnionPay"
    if (d.startswith("50") or 56 <= p2 <= 69) and 12 <= n <= 19:
        return "Maestro"
    return None


# --------------------------------------------------------------------------- patterns

_EMAIL_RE = re.compile(
    r"(?<![\w.+%-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![\w-])"
)
_FILE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "js", "css", "ts", "py", "json", "md", "txt", "pdf", "ico", "map"}
_CARD_RE = re.compile(r"(?<![\d\-.])(\d(?:[ \-]?\d){11,18})(?![\d])(?!-\d)")
_PESEL_RE = re.compile(r"(?<![\d\-./])(\d{11})(?![\d])(?![.,/]\d)")
_NIP_RE = re.compile(
    r"(?<![\w\-./])(?:PL[ ]?)?(\d{3}-\d{3}-\d{2}-\d{2}|\d{3}-\d{2}-\d{2}-\d{3}|\d{3} \d{3} \d{2} \d{2}|\d{10})(?![\w\-])(?![.,/]\d)"
)
_NIP_CONTEXT_RE = re.compile(r"(?i)\b(?:nip|tax\s*id|vat(?:\s*(?:id|number|no))?|nr\s*nip|numer\s*nip|vat-?id)\b[^\n\d]{0,20}$")
_IBAN_RE = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2}\d{2}(?:[ \-]?[A-Z0-9]){10,30})")
_NRB_RE = re.compile(r"(?<![\w\-])(\d{2}(?:[ \-]?\d{4}){6})(?![\w\-])")
_PHONE_RE = re.compile(
    r"(?<![\w+/.\-])("
    r"(?:\+|00)\d{1,3}[ \-.]?(?:\(\d{1,4}\)[ \-.]?)?\d{2,4}(?:[ \-.]?\d{2,4}){1,4}"  # international
    r"|\(\d{2,4}\)[ \-]?\d{3}[ \-]?\d{2,4}(?:[ \-]?\d{2,4})?"  # (22) 123 45 67, (555) 123-4567
    r"|[1-9]\d{2}[ \-]\d{3}[ \-]\d{3}"  # 600 123 456
    r"|[1-9]\d[ \-]\d{3}[ \-]\d{2}[ \-]\d{2}"  # 22 123 45 67
    r"|\d{3}-\d{3}-\d{4}"  # 555-123-4567
    r"|[1-9]\d{8}"  # 600123456 (needs context)
    r")(?![\w])(?![.,]\d)"
)
_PHONE_CONTEXT_RE = re.compile(
    r"(?i)(?:\btel\b|\btel\.|\btelephone|\bphone|\btelefon\w*|\bmobile\b|\bcell\b|\bkom\.|\bkomork\w*|\bkomórk\w*|"
    r"\bcall\b|\bcalls?\s+(?:me|us|him|her|them)|\bring\b|\btext\s+(?:me|us)|\breach\s+(?:me|us|him|her)|\bdial\b|"
    r"\bzadzwo\w*|\bdzwo\w*|\boddzwo\w*|\bsms\b|\bwhatsapp\b|\bsignal\b|\bfax\b|\bhotline\b|\binfolinia\w*|"
    r"\bnumer\w*\s+(?:kontaktow\w*|telefon\w*|komórk\w*|komork\w*)|\bnr\.?\s*tel|\bmy number|\bmój numer|\bmoj numer|"
    r"\bcontact\s*(?:number|no\.?|details|me|us)?)"
)
# Identifier context: a grouped number right after these words is an order, invoice or case number.
_ID_CONTEXT_RE = re.compile(
    r"(?i)(?:\border|\bzamówieni\w*|\bzamowieni\w*|\breference|\bref\b\.?|\bticket|\binvoice|\bfaktur\w*|"
    r"\bcase\b|\bsprawy\b|\bsprawa\b|\bzgłoszeni\w*|\bzgloszeni\w*|\btracking|\bprzesyłk\w*|\bprzesylk\w*|\bparcel|"
    r"\bshipment|\bpo\b|\bpurchase|\btransaction|\btransakcj\w*|\bcontract|\bumow\w*|\bpolicy|\bpolis\w*|"
    r"\bcustomer\s+(?:id|no|number)|\bclient\s+(?:id|no|number)|\bnumer\s+klienta|\bid\b|\bsku\b|\bserial|"
    r"\bbatch|\bpartia|\bdocument|\bdokument\w*|\baccount\s+(?:id|no|number)|\bloan|\bkredyt\w*|\bclaim|\bszkod\w*)"
)
_INTL_RE = re.compile(r"^(?:\+|00)")
_PAREN_RE = re.compile(r"^\(")


def _phone_context(before: str, after: str) -> bool:
    """True when the nearest cue before the number says phone (and no closer cue says order/invoice id)."""
    pos = [m.end() for m in _PHONE_CONTEXT_RE.finditer(before)]
    neg = [m.end() for m in _ID_CONTEXT_RE.finditer(before)]
    if pos and (not neg or pos[-1] > neg[-1]):
        return True
    if re.match(r"^\s*\((?:tel|phone|mobile|cell|kom|komórka|komorka|fax)\b", after, re.I):
        return True
    return False


def _id_context(before: str) -> bool:
    pos = [m.end() for m in _PHONE_CONTEXT_RE.finditer(before)]
    neg = [m.end() for m in _ID_CONTEXT_RE.finditer(before)]
    return bool(neg) and (not pos or neg[-1] > pos[-1])


_AMOUNT_AFTER_RE = re.compile(r"^\s?(?:zł|zl|pln|eur|usd|gbp|chf|\$|€|£|k\b|mln|tys)", re.I)
_AMOUNT_BEFORE_RE = re.compile(r"(?i)(?:\$|€|£|pln|eur|usd|kwot\w*|amount|total|suma|saldo|balance|price|cena)\s*[:=]?\s*$")


class PiiControl(Control):
    id = "pii"
    owasp_llm = ["LLM02"]
    owasp_agentic: list[str] = []

    def __init__(self, cfg: PiiCfg, policy_doc: Any = None) -> None:
        super().__init__(cfg, policy_doc)
        self.entity_actions: dict[str, Action] = {e: Action.parse(a) for e, a in cfg.entities.items()}
        self.visible_for = frozenset(cfg.output_visible_for_clearance)

    # ------------------------------------------------------------------ detection
    def find(self, text: str) -> list[PiiHit]:
        text = text[:MAX_SCAN_CHARS]
        want = self.entity_actions
        cands: list[PiiHit] = []
        has_digit = any(c.isdigit() for c in text)
        if "IBAN" in want and has_digit:
            cands.extend(self._ibans(text))
        if "CREDIT_CARD" in want and has_digit:
            for m in _CARD_RE.finditer(text):
                d = _digits(m.group(1))
                if 13 <= len(d) <= 19 and luhn_valid(d) and card_brand(d) and len(set(d)) > 1:
                    cands.append(PiiHit("CREDIT_CARD", m.start(1), m.end(1), m.group(1)))
        if "PESEL" in want and has_digit:
            for m in _PESEL_RE.finditer(text):
                if pesel_valid(_digits(m.group(1))):
                    cands.append(PiiHit("PESEL", m.start(1), m.end(1), m.group(1)))
        if "NIP" in want and has_digit:
            for m in _NIP_RE.finditer(text):
                raw = m.group(0)
                d = _digits(m.group(1))
                if not nip_valid(d):
                    continue
                formatted = "-" in raw or " " in m.group(1) or raw.upper().startswith("PL")
                if not formatted and not _NIP_CONTEXT_RE.search(text[max(0, m.start() - 40) : m.start()]):
                    continue
                cands.append(PiiHit("NIP", m.start(), m.end(), raw))
        if "PHONE" in want and has_digit:
            for m in _PHONE_RE.finditer(text):
                v = m.group(1)
                d = _digits(v)
                if not 9 <= len(d) <= 15:
                    continue
                before = text[max(0, m.start() - 48) : m.start()]
                after = text[m.end() : m.end() + 16]
                if _AMOUNT_AFTER_RE.match(after) or _AMOUNT_BEFORE_RE.search(before):
                    continue
                if _INTL_RE.match(v):
                    # +48 600 123 456 is a phone without further context; a compact 0048600123456 needs context
                    if v.startswith("00") and v.isdigit() and not _phone_context(before, after):
                        continue
                elif _PAREN_RE.match(v):
                    if _id_context(before):
                        continue  # (22) 123 45 67 layout is a phone unless the text calls it an id
                elif not _phone_context(before, after):
                    continue  # 600 123 456 / 600123456 / 555-123-4567 are ids or amounts unless the text says phone
                cands.append(PiiHit("PHONE", m.start(1), m.end(1), v))
        if "EMAIL" in want and "@" in text:
            for m in _EMAIL_RE.finditer(text):
                v = m.group(1)
                tld = v.rsplit(".", 1)[-1].lower()
                if tld in _FILE_TLDS:
                    continue
                if v.lower().startswith("git@") and text[m.end() : m.end() + 1] == ":":
                    continue  # git@github.com:org/repo.git is an SSH remote, not a person
                cands.append(PiiHit("EMAIL", m.start(1), m.end(1), v))
        # resolve overlaps by specificity
        cands.sort(key=lambda h: (PRIORITY[h.entity], h.start))
        kept: list[PiiHit] = []
        for h in cands:
            if any(not (h.end <= k.start or h.start >= k.end) for k in kept):
                continue
            kept.append(h)
        return sorted(kept, key=lambda h: h.start)

    def _ibans(self, text: str) -> list[PiiHit]:
        out: list[PiiHit] = []
        for m in _IBAN_RE.finditer(text):
            # Take exactly the country's length worth of characters, then verify the boundary.
            start = m.start(1)
            country = text[start : start + 2].upper()
            exp = IBAN_LENGTHS.get(country)
            if exp is None:
                continue
            n, i = 0, start
            while i < len(text) and n < exp:
                c = text[i]
                if c.isalnum():
                    n += 1
                elif c not in " -" or i == start:
                    break
                i += 1
            if n != exp or (i < len(text) and text[i].isalnum()):
                continue
            value = text[start:i]
            if iban_valid(value.replace("-", "")):
                out.append(PiiHit("IBAN", start, i, value))
        for m in _NRB_RE.finditer(text):
            d = _digits(m.group(1))
            if len(d) == 26 and iban_valid("PL" + d):
                out.append(PiiHit("IBAN", m.start(1), m.end(1), m.group(1)))
        return out

    # ------------------------------------------------------------------ control API
    def scan(self, segment: Segment, views: list[View], ctx: ScanContext) -> list[Finding]:
        if not self.entity_actions:
            return []
        raw = views[0].text if views and views[0].kind == "raw" else segment.text
        visible = (
            ctx is not None
            and getattr(ctx, "principal", None) is not None
            and ctx.principal.data_clearance in self.visible_for
            and segment.direction in ("output", "tool_result")
        )
        findings: list[Finding] = []
        seen: set[str] = set()
        for h in self.find(raw):
            seen.add(_digits(h.value) or h.value.lower())
            findings.append(self._finding(segment, h, (h.start, h.end), "raw", visible, ctx))
        for v in views[1:]:
            if v.kind not in ("decoded:base64", "decoded:hex", "decoded:url"):
                continue
            for h in self.find(v.text):
                key = _digits(h.value) or h.value.lower()
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._finding(segment, h, v.span, v.kind, visible, ctx))
        return findings

    def _finding(
        self, segment: Segment, h: PiiHit, span: tuple[int, int] | None, view: str, visible: bool, ctx: ScanContext | None
    ) -> Finding:
        action = self.entity_actions[h.entity]
        downgraded = False
        if visible and action == Action.REDACT:
            action = Action.LOG
            downgraded = True
        if span is None and action == Action.REDACT:
            action = Action.BLOCK
        title = TITLES[h.entity]
        where = WHERE.get(segment.direction, "in the text")
        token = f"[REDACTED:{h.entity}]"
        enc = f" inside a {view.split(':', 1)[1]}-encoded blob" if view.startswith("decoded:") else ""
        if downgraded:
            clearance = ctx.principal.data_clearance if ctx is not None else ""
            msg = (
                f"{title}{enc} {where} was logged, not redacted: principal clearance '{clearance}' is allowed to see "
                "personal data in responses (pii.output_visible_for_clearance)."
            )
        elif action == Action.REDACT:
            what = "the whole blob was" if enc else "it was"
            msg = (
                f"{title}{enc} {where}: {what} replaced with {token}. Personal data is shared only on a need-to-know "
                "basis; ask for an agent with higher data clearance if this data is required."
            )
        elif action == Action.BLOCK:
            msg = (
                f"{title}{enc} {where}: the request was blocked (pii.entities.{h.entity} is block). Remove the "
                "number or use a masked form such as the last four digits."
            )
        elif action == Action.REQUIRE_APPROVAL:
            msg = f"{title}{enc} {where}: held for human approval (pii.entities.{h.entity} is require_approval)."
        else:
            msg = f"{title}{enc} {where} was logged (pii.entities.{h.entity} is {action.label}); no change was made."
        return Finding(
            control=self.id,
            rule=h.entity,
            severity="high" if h.entity in ("CREDIT_CARD", "PESEL", "IBAN") else "medium",
            action=action,
            message=msg,
            span=span,
            evidence=_evidence(h),
            owasp_llm=list(self.owasp_llm),
            owasp_agentic=[],
            atlas=list(ATLAS),
            view=view,
        )


def _evidence(h: PiiHit) -> str:
    v = h.value
    if h.entity == "EMAIL":
        local, _, domain = v.partition("@")
        return f"{local[:1]}***@{domain}"
    d = _digits(v)
    if h.entity == "CREDIT_CARD":
        return mask(d, 0, 4)
    if h.entity == "IBAN":
        compact = v.replace(" ", "").replace("-", "")
        return mask(compact, 4, 4)
    if h.entity == "PHONE":
        return mask(v.replace(" ", ""), 3, 2)
    return mask(d, 2, 2)
