"""Secrets detection (control id "secrets"): gitleaks-style provider rules plus an entropy fallback.

Scan order per segment:
  1. raw view: exact spans, so the pipeline can replace the value with [REDACTED:<rule>];
  2. raw text with string concatenations joined ("AKIA" + "IOSF..."): spans mapped back to the raw text,
     so a split secret is still redacted in place;
  3. normalized:case view (NFKC, lookalike letters folded): a secret visible only here cannot be redacted
     in place, so it is reported without a span and with action block;
  4. decoded views (base64 / hex / url): span = the whole encoded blob.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from bouncer.core import Action, Control, Finding, ScanContext, Segment, View, mask
from bouncer.policy.schema import SecretsCfg

MAX_SCAN_CHARS = 200_000

ATLAS = ["AML.T0055", "AML.T0057"]  # Unsecured Credentials, LLM Data Leakage (verified in mitre-atlas/atlas-data)

WHERE = {
    "input": "in the prompt",
    "output": "in the model response",
    "tool_call": "in tool call arguments",
    "tool_result": "in a tool result",
    "tool_definition": "in a tool definition",
}


@dataclass(frozen=True, slots=True)
class Hit:
    rule: str
    start: int
    end: int
    value: str
    severity: str


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    pattern: re.Pattern[str]
    group: int = 1
    severity: str = "high"
    keywords: tuple[str, ...] = ()  # cheap prefilter: at least one must occur (case-sensitive)
    ikeywords: tuple[str, ...] = ()  # same, case-insensitive (checked against lowercased text)
    validate: Callable[[re.Match[str], str], str | None] | None = None  # returns severity, or None to drop


# --------------------------------------------------------------------------- helpers

_PLACEHOLDER_WORDS = {
    "password", "passwd", "pass", "pwd", "secret", "null", "none", "nil", "true", "false", "undefined",
    "redacted", "hidden", "masked", "example", "test", "token", "apikey", "api_key", "key", "value",
    "string", "your_password", "yourpassword", "changeit", "placeholder", "xxx", "todo", "tbd", "empty",
    "required", "optional", "str", "bool", "int", "env", "default",
}
_PLACEHOLDER_RE = re.compile(
    r"^(?:<[^>]*>|\$\{[^}]*\}?|\{\{[^}]*\}?\}?|%\([^)]*\)s?|\$\([^)]*\)?|\$[A-Za-z_][A-Za-z0-9_]*|\[REDACTED[^\]]*\]?|\*+|x+|X+|\.+|…+|-+|_+|#+)$"
)
_PLACEHOLDER_SUB_RE = re.compile(
    r"(?i)(?:\.\.\.|…|xxxx|\*\*\*|<[a-z_ -]+>|your[_ -]?(?:api|secret|token|key|pass|own)|\[redacted|"
    r"replace[_ -]?me|change[_ -]?me|insert[_ -]?(?:your|key|token|here)|example[_-](?:key|token|secret|password))"
)
_REFERENCE_RE = re.compile(
    r"^(?:os\.environ|os\.getenv|process\.env|env\(|getenv|settings\.|config\.|secrets\.|vault:|"
    r"ENV\[|System\.getenv|\$env:|import\b|require\()"
)
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")


def _is_placeholder(value: str, strict: bool = True) -> bool:
    v = value.strip().strip("\"'`")
    if not v:
        return True
    if _PLACEHOLDER_RE.match(v) or _PLACEHOLDER_SUB_RE.search(v):
        return True
    if len(set(v)) <= 3:
        return True
    if not strict:
        return False
    low = v.lower()
    if low in _PLACEHOLDER_WORDS or _REFERENCE_RE.match(v) or _ENV_NAME_RE.match(v):
        return True
    return "(" in v and v.endswith(")")


def _secretish(value: str) -> bool:
    """A free-text value that looks like a credential rather than an English word."""
    v = value.rstrip(".,!?;:")
    if len(v) < 6:
        return False
    has_alpha = any(c.isalpha() for c in v)
    has_digit = any(c.isdigit() for c in v)
    has_symbol = any(not c.isalnum() for c in v)
    inner_upper = re.search(r"[a-z][A-Z]", v) is not None
    return has_alpha and (has_digit or has_symbol or inner_upper)


def shannon(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for c in value:
        counts[c] = counts.get(c, 0) + 1
    n = len(value)
    return -sum(k / n * math.log2(k / n) for k in counts.values())


def _b64url_json(seg: str) -> Any:
    s = seg + "=" * (-len(seg) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(s).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


# --------------------------------------------------------------------------- validators


def _v_not_placeholder(m: re.Match[str], sev: str) -> str | None:
    return None if _is_placeholder(m.group(1), strict=False) else sev


def _v_aws_split(m: re.Match[str], sev: str) -> str | None:
    body = m.group(2)
    compact = re.sub(r"[ \-_.]", "", body)
    if compact == body:
        return None  # the compact rule already covers it
    return sev if any(c.isdigit() for c in compact) else None


def _v_mixed_b64(m: re.Match[str], sev: str) -> str | None:
    v = m.group(1)
    if _is_placeholder(v, strict=False):
        return None
    classes = sum((any(c.islower() for c in v), any(c.isupper() for c in v), any(c.isdigit() for c in v)))
    return sev if classes >= 2 else None


def _v_stripe(m: re.Match[str], sev: str) -> str | None:
    v = m.group(1)
    if _is_placeholder(v, strict=False):
        return None
    return "critical" if "_live_" in v else "low"


def _v_api_key(m: re.Match[str], sev: str) -> str | None:
    v = m.group(1)
    if _is_placeholder(v, strict=False):
        return None
    body = v.split("-", 1)[-1]
    if not (any(c.isdigit() for c in body) and any(c.isalpha() for c in body)) or len(set(body)) < 8:
        return None
    return sev


def _v_jwt(m: re.Match[str], sev: str) -> str | None:
    header = _b64url_json(m.group(2))
    if not isinstance(header, dict) or not ({"alg", "typ"} & set(header)):
        return None
    return sev


def _v_pem(m: re.Match[str], sev: str) -> str | None:
    body = m.group("body") or ""
    b64 = re.sub(r"\\n|\\r|\s|[^A-Za-z0-9+/=]", "", body.split("-----END")[0])
    if re.search(r"Proc-Type|DEK-Info", body):
        return sev  # encrypted PEM is still a private key
    return sev if len(b64) >= 8 else None


def _v_sas(m: re.Match[str], sev: str) -> str | None:
    start = max(0, m.start() - 400)
    window = m.string[start : m.end()]
    return sev if re.search(r"[?&](?:sv|se|sp|sr)=", window) else None


def _v_conn(m: re.Match[str], sev: str) -> str | None:
    pw = m.group(1)
    if _is_placeholder(pw) or pw.lower() in {"pass", "pw", "pwd", "password", "secret", "user", "admin"}:
        return None
    return sev


# --------------------------------------------------------------------------- rules (priority order)

_X = re.VERBOSE

RULES: list[Rule] = [
    Rule("private-key", "Private key", re.compile(
        r"(-----BEGIN[ A-Z0-9_-]{0,40}PRIVATE KEY(?: BLOCK)?-----(?P<body>[\s\S]{0,12000}?)"
        r"-----END[ A-Z0-9_-]{0,40}PRIVATE KEY(?: BLOCK)?-----)"), 1, "critical",
        keywords=("PRIVATE KEY",), validate=_v_pem),
    Rule("private-key", "Private key (truncated)", re.compile(
        r"(-----BEGIN[ A-Z0-9_-]{0,40}PRIVATE KEY(?: BLOCK)?-----(?P<body>(?:\\n|\\r|\s)*[A-Za-z0-9+/=]{40,}"
        r"(?:(?:\\n|\\r|\s)+[A-Za-z0-9+/=]{4,}){0,200}))"), 1, "critical",
        keywords=("PRIVATE KEY",), validate=_v_pem),
    Rule("gcp-service-account", "GCP service account key id", re.compile(
        r"\"private_key_id\"\s*:\s*\"([0-9a-f]{40})\""), 1, "critical", keywords=("private_key_id",)),
    Rule("aws-access-key-id", "AWS access key id", re.compile(
        r"(?<![A-Z0-9])((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})(?![A-Z0-9])"), 1, "high",
        keywords=("AKIA", "ASIA", "ABIA", "ACCA", "A3T")),
    Rule("aws-access-key-id", "AWS access key id (split with separators)", re.compile(
        r"(?<![A-Z0-9])((?:AKIA|ASIA)((?:[ \-_.]?[A-Z0-9]){16}))(?![A-Z0-9])"), 1, "high",
        keywords=("AKIA", "ASIA"), validate=_v_aws_split),
    Rule("aws-secret-access-key", "AWS secret access key", re.compile(
        r"(?i:aws_?secret_?access_?key|aws_?secret_?key|secret_?access_?key|aws_?secret)[\"']?\s*(?:[:=]|=>|:=)?\s*"
        r"[\"']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"), 1, "critical",
        ikeywords=("secret",), validate=_v_mixed_b64),
    Rule("gcp-api-key", "Google API key", re.compile(r"(?<![\w-])(AIza[0-9A-Za-z_\-]{35})(?![\w-])"), 1, "high",
         keywords=("AIza",), validate=_v_not_placeholder),
    Rule("azure-storage-account-key", "Azure storage account key", re.compile(
        r"(?i:AccountKey)\s*=\s*([A-Za-z0-9+/]{20,100}={0,2})"), 1, "critical", ikeywords=("accountkey",),
        validate=_v_not_placeholder),
    Rule("azure-sas-token", "Azure SAS token signature", re.compile(
        r"[?&]sig=([A-Za-z0-9%+/=]{20,})"), 1, "high", keywords=("sig=",), validate=_v_sas),
    Rule("azure-ad-client-secret", "Azure AD client secret", re.compile(
        r"(?<![\w~.-])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?![\w~.-])"), 1, "high", keywords=("Q~",)),
    Rule("github-fine-grained-pat", "GitHub fine-grained token", re.compile(
        r"(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])"), 1, "high",
        keywords=("github_pat_",), validate=_v_not_placeholder),
    Rule("github-pat", "GitHub token", re.compile(
        r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{20,255})(?![A-Za-z0-9_])"), 1, "high",
        keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), validate=_v_not_placeholder),
    Rule("gitlab-pat", "GitLab token", re.compile(
        r"(?<![\w-])(gl(?:pat|ptt|dt|rt|cbt|ft|imt)-[A-Za-z0-9_\-]{20,})(?![\w-])"), 1, "high",
        keywords=("gl",), validate=_v_not_placeholder),
    Rule("slack-webhook-url", "Slack webhook URL", re.compile(
        r"((?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9_/+-]{20,})"), 1, "high",
        keywords=("hooks.slack.com",)),
    Rule("slack-token", "Slack token", re.compile(
        r"(?<![\w-])(xox[abposre]-[A-Za-z0-9-]{10,}|xapp-\d-[A-Za-z0-9-]{10,})(?![\w-])"), 1, "high",
        keywords=("xox", "xapp-"), validate=_v_not_placeholder),
    Rule("stripe-secret-key", "Stripe secret key", re.compile(
        r"(?<!\w)((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,247})(?!\w)"), 1, "critical",
        keywords=("_live_", "_test_"), validate=_v_stripe),
    Rule("anthropic-api-key", "Anthropic API key", re.compile(
        r"(?<![\w-])(sk-ant-[A-Za-z0-9_-]{20,})(?![\w-])"), 1, "critical", keywords=("sk-ant-",),
        validate=_v_api_key),
    Rule("openai-api-key", "OpenAI API key", re.compile(
        r"(?<![\w-])(sk-(?!ant-)(?:proj-|svcacct-|admin-|None-)?[A-Za-z0-9_-]{20,})(?![\w-])"), 1, "critical",
        keywords=("sk-",), validate=_v_api_key),
    Rule("huggingface-token", "Hugging Face token", re.compile(r"(?<!\w)(hf_[A-Za-z0-9]{30,})(?!\w)"), 1, "high",
         keywords=("hf_",), validate=_v_api_key),
    Rule("npm-token", "npm token", re.compile(r"(?<!\w)(npm_[A-Za-z0-9]{36})(?!\w)"), 1, "high", keywords=("npm_",)),
    Rule("sendgrid-api-key", "SendGrid API key", re.compile(
        r"(?<![\w.])(SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64})(?![\w.])"), 1, "high", keywords=("SG.",)),
    Rule("google-oauth-client-secret", "Google OAuth client secret", re.compile(
        r"(?<![\w-])(GOCSPX-[A-Za-z0-9_-]{24,32})(?![\w-])"), 1, "high", keywords=("GOCSPX-",)),
    Rule("jwt", "JSON Web Token", re.compile(
        r"(?<![\w.-])((eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,1024})(?![\w.-])"), 1, "medium",
        keywords=("eyJ",), validate=_v_jwt),
    Rule("connection-string", "Database or service connection string with a password", re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|oracle|"
        r"jdbc:[a-z]+|s?ftp|smtps?|ldaps?|https?|git\+https?|ssh)://[^\s:@/'\"<>]{1,128}:([^\s@/'\"<>]{1,256})@"
        r"[A-Za-z0-9.\-_\[\]]+"), 1, "high", keywords=("://",), validate=_v_conn),
    Rule("authorization-header", "Authorization header credential", re.compile(
        r"(?i)\b(?:authorization|proxy-authorization)[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token|bot|apikey)\s+"
        r"([A-Za-z0-9._~+/=-]{12,})"), 1, "high", ikeywords=("authorization",), validate=_v_not_placeholder),
    Rule("authorization-header", "Bearer token", re.compile(
        r"(?<![\w-])[Bb]earer\s+([A-Za-z0-9._~+/-]{24,}=*)"), 1, "high", ikeywords=("bearer",),
        validate=_v_api_key),
]

# password-assignment is implemented in code (needs context-dependent value checks).
_KEYWORD = (
    r"(?:password|passwd|passphrase|pwd|secret|secret[_-]?key|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|bearer[_-]?token|"
    r"session[_-]?token|token|has[łl]o|credentials?|klucz[_-]?api)"
)
_ASSIGN_RE = re.compile(
    r"(?i)(?<![\w.\-])(?P<key>[A-Za-z0-9_.\-]{0,40}?" + _KEYWORD + r")(?![A-Za-z0-9])[\"'`]?"
    r"(?P<op>\s{0,3}(?:=|:=|=>|:|->)\s{0,3})"
    r"(?:\"(?P<dq>[^\"\n]{3,300})\"|'(?P<sq>[^'\n]{3,300})'|`(?P<bq>[^`\n]{3,300})`|(?P<bare>[^\s\"'`,;&<>{}()\[\]]{3,300}))"
)
_ANCHORS = ("pass", "pwd", "secret", "key", "token", "has", "credential", "klucz", "pin")


def _candidate_lines(low: str, anchors: tuple[str, ...]) -> list[tuple[int, int]]:
    """Line spans that contain at least one anchor substring (cheap C-level find instead of a regex scan)."""
    spans: set[tuple[int, int]] = set()
    n = len(low)
    for a in anchors:
        i = low.find(a)
        while i != -1:
            ls = low.rfind("\n", 0, i) + 1
            le = low.find("\n", i)
            le = n if le == -1 else le
            spans.add((ls, le))
            i = low.find(a, le)
    return sorted(spans)


_KW_ASSIGN_RE = re.compile(r"(?i)" + _KEYWORD + r"(?![A-Za-z0-9])[\"'`]?\s{0,3}(?:=|:=|=>|:|->)")
_IDENT_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
_NL_RE = re.compile(
    r"(?i)\b(?:password|passcode|pin|api key|access token|token|secret|has[łl]o|klucz api)"
    r"\s+(?:is|was|jest|to|brzmi)\s*:?\s+[\"']?(?P<val>[^\s\"']{6,100})"
)
_NUMERIC_OK_KEYS = re.compile(r"(?i)(?:password|passwd|pwd|pin|has[łl]o|passphrase)$")

# AWS secret next to an access key id: any 40-char base64 token with mixed case and digits.
_AWS_SECRET_NEAR_RE = re.compile(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])")

# Entropy candidates.
_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/_\-])([A-Za-z0-9+/_\-]{8,512}={0,2})(?![A-Za-z0-9+/=_\-])")
_CONTEXT_RE = re.compile(
    r"(?i)(?:key|token|secret|passw|pwd|credential|auth|bearer|api|signature|\bsig\b|has[łl]|klucz|private|"
    r"session|cookie|sas)"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_UUIDISH_RE = re.compile(r"^[0-9a-fA-F-]+$")
_CONCAT_RE = re.compile(r"""(?<=[\w/+=-])["'`]\s*(?:\+|\.|\|\||&)?\s*["'`](?=[\w/+=-])""")


def _join_with_map(text: str) -> tuple[str, list[int]] | None:
    """Join concatenated string literals, keeping a map from joined offsets to raw offsets."""
    if '"' not in text and "'" not in text and "`" not in text:
        return None
    pieces: list[str] = []
    idx: list[int] = []
    last = 0
    for m in _CONCAT_RE.finditer(text):
        pieces.append(text[last : m.start()])
        idx.extend(range(last, m.start()))
        last = m.end()
    if not pieces:
        return None
    pieces.append(text[last:])
    idx.extend(range(last, len(text)))
    return "".join(pieces), idx


def _decodes_to_text(token: str) -> bool:
    s = token.rstrip("=")
    if "-" in s or "_" in s:
        s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s, validate=True)
        txt = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    return len(txt) >= 6 and sum(c.isprintable() for c in txt) / len(txt) > 0.9


class SecretsControl(Control):
    id = "secrets"
    owasp_llm = ["LLM02"]
    owasp_agentic = ["ASI03"]

    def __init__(self, cfg: SecretsCfg, policy_doc: Any = None) -> None:
        super().__init__(cfg, policy_doc)
        all_ids = {r.id for r in RULES} | {"password-assignment", "high-entropy-string"}
        if cfg.rules == "builtin":
            enabled = set(all_ids)
        else:
            enabled = {r for r in cfg.rules if r in all_ids}
        self.enabled = frozenset(enabled)
        self.rules = tuple(r for r in RULES if r.id in self.enabled)
        self.password_rule = "password-assignment" in self.enabled
        self.entropy = cfg.entropy if (cfg.entropy.enabled and "high-entropy-string" in self.enabled) else None
        self.allow_values = frozenset(cfg.allow_values)
        default = Action.parse(cfg.action)
        self.actions: dict[str, Action] = {rid: Action.parse(cfg.overrides.get(rid, cfg.action)) for rid in all_ids}
        ent_action = cfg.overrides.get("high-entropy-string") or cfg.entropy.action or cfg.action
        self.actions["high-entropy-string"] = Action.parse(ent_action)
        self.default_action = default
        self.priority = {rid: i for i, rid in enumerate(dict.fromkeys([r.id for r in RULES] + ["password-assignment", "high-entropy-string"]))}

    # ------------------------------------------------------------------ text scanning
    def find(self, text: str) -> list[Hit]:
        """All secrets in text with exact spans (overlaps resolved)."""
        text = text[:MAX_SCAN_CHARS]
        hits: list[Hit] = []
        lower: str | None = None
        for rule in self.rules:
            if rule.keywords and not any(k in text for k in rule.keywords):
                continue
            if rule.ikeywords:
                lower = lower if lower is not None else text.lower()
                if not any(k in lower for k in rule.ikeywords):
                    continue
            for m in rule.pattern.finditer(text):
                sev = rule.severity
                if rule.validate is not None:
                    sev = rule.validate(m, sev)
                    if sev is None:
                        continue
                value = m.group(rule.group)
                if value in self.allow_values:
                    continue
                hits.append(Hit(rule.id, m.start(rule.group), m.end(rule.group), value, sev))
        if self.password_rule:
            hits.extend(self._password_hits(text))
        if "aws-secret-access-key" in self.enabled and any(h.rule == "aws-access-key-id" for h in hits):
            for m in _AWS_SECRET_NEAR_RE.finditer(text):
                v = m.group(1)
                if all(any(f(c) for c in v) for f in (str.islower, str.isupper, str.isdigit)) and v not in self.allow_values:
                    hits.append(Hit("aws-secret-access-key", m.start(1), m.end(1), v, "critical"))
        hits = self._resolve(hits)
        if self.entropy is not None:
            hits = self._resolve(hits + self._entropy_hits(text, hits))
        return hits

    def _password_hits(self, text: str) -> list[Hit]:
        out: list[Hit] = []
        low = text.lower()
        if len(low) != len(text):
            low = text  # case mapping changed the length: fall back to scanning everything
            lines = [(0, len(text))]
        else:
            lines = _candidate_lines(low, _ANCHORS)
        for ls, le in lines:
            self._password_hits_in(text, ls, le, out)
        return out

    def _password_hits_in(self, text: str, ls: int, le: int, out: list[Hit]) -> None:
        last_end = -1
        for km in _KW_ASSIGN_RE.finditer(text, ls, le):
            if km.start() < last_end:
                continue
            i = km.start()
            while i > 0 and km.start() - i < 40 and text[i - 1] in _IDENT_CHARS:
                i -= 1
            m = _ASSIGN_RE.match(text, i)
            if m is None:
                continue
            last_end = m.end()
            key = m.group("key")
            op = m.group("op")
            for g in ("dq", "sq", "bq", "bare"):
                if m.group(g) is not None:
                    group = g
                    break
            value = m.group(group)
            start, end = m.start(group), m.end(group)
            if len(value) < 4 or value in self.allow_values or _is_placeholder(value):
                continue
            if group == "bare":
                # keep "!" and "?" (likely part of the password); drop sentence punctuation
                stripped = value.rstrip(".,:")
                end -= len(value) - len(stripped)
                value = stripped
                if len(value) < 4 or _is_placeholder(value):
                    continue
            if value.isdigit() and not _NUMERIC_OK_KEYS.search(key):
                continue
            if group == "bare":
                if text[m.end(group) : m.end(group) + 1] in ("(", "["):
                    continue  # an expression: get_password(), cfg["pw"]
                spaced = op != op.strip()
                line_end = text.find("\n", end)
                rest = text[end : line_end if line_end != -1 else len(text)].strip()
                if ":" in op and spaced and rest and not _secretish(value):
                    continue  # prose like "Password: must be 12 characters"
                if "=" in op and spaced and re.fullmatch(r"[A-Za-z_][A-Za-z_]*", value):
                    continue  # code: password = user_password
                if ":" in op and not _secretish(value) and re.fullmatch(r"[a-z]+", value) and len(value) < 8:
                    continue
            out.append(Hit("password-assignment", start, end, value, "high"))
        for m in _NL_RE.finditer(text, ls, le):
            value = m.group("val").rstrip(".,:;")
            if not _secretish(value) or _is_placeholder(value) or value in self.allow_values:
                continue
            out.append(Hit("password-assignment", m.start("val"), m.start("val") + len(value), value, "high"))

    def _entropy_hits(self, text: str, found: list[Hit]) -> list[Hit]:
        cfg = self.entropy
        assert cfg is not None
        out: list[Hit] = []
        spans = [(h.start, h.end) for h in found]
        for m in _TOKEN_RE.finditer(text):
            tok = m.group(1)
            if len(tok) < cfg.min_length:
                continue
            s, e = m.start(1), m.end(1)
            if any(not (e <= a or s >= b) for a, b in spans):
                continue
            if tok in self.allow_values or _HEX_RE.match(tok) or _UUIDISH_RE.match(tok):
                continue
            core = tok.rstrip("=")
            lowers = any(c.islower() for c in core)
            uppers = any(c.isupper() for c in core)
            digits = any(c.isdigit() for c in core)
            if not digits or not (lowers or uppers):
                continue
            if tok.count("/") >= 3 or tok.count("-") >= 4 or tok.count("_") >= 4:
                continue  # paths, slugs, identifiers
            ent = shannon(core)
            if ent < cfg.min_bits_per_char:
                continue
            # skip tokens inside URLs and data URIs
            ws = max(text.rfind(" ", 0, s), text.rfind("\n", 0, s), text.rfind("(", 0, s), text.rfind('"', 0, s))
            word_prefix = text[ws + 1 : s]
            if "://" in word_prefix or word_prefix.endswith("base64,") or "data:" in word_prefix:
                continue
            if _decodes_to_text(core):
                continue
            line_start = text.rfind("\n", 0, s) + 1
            context = text[max(line_start, s - 48) : s]
            has_context = _CONTEXT_RE.search(context) is not None
            if not has_context:
                strong = lowers and uppers and digits and len(core) >= 32 and ent >= cfg.min_bits_per_char + 0.3
                if not strong:
                    continue
            out.append(Hit("high-entropy-string", s, e, tok, "medium"))
        return out

    def _resolve(self, hits: list[Hit]) -> list[Hit]:
        """Drop duplicates and overlapping hits: keep the stronger action, then the more specific rule."""
        if len(hits) < 2:
            return hits

        def rank(h: Hit) -> tuple[int, int, int]:
            return (int(self.actions.get(h.rule, self.default_action)), -self.priority.get(h.rule, 99), h.end - h.start)

        kept: list[Hit] = []
        for h in sorted(hits, key=rank, reverse=True):
            if any(not (h.end <= k.start or h.start >= k.end) for k in kept):
                continue
            kept.append(h)
        return sorted(kept, key=lambda h: h.start)

    # ------------------------------------------------------------------ control API
    def scan(self, segment: Segment, views: list[View], ctx: ScanContext) -> list[Finding]:
        raw_view = views[0] if views and views[0].kind == "raw" else View(segment.text, "raw")
        raw = raw_view.text
        findings: list[Finding] = []
        seen_values: set[str] = set()

        for h in self.find(raw):
            seen_values.add(h.value)
            findings.append(self._finding(segment, h, (h.start, h.end), "raw", None))

        joined = _join_with_map(raw[:MAX_SCAN_CHARS])
        if joined is not None:
            jtext, idx = joined
            for h in self.find(jtext):
                if h.value in seen_values or h.value in raw:
                    continue
                seen_values.add(h.value)
                span = (idx[h.start], idx[h.end - 1] + 1)
                findings.append(self._finding(segment, h, span, "raw", "split"))

        for v in views[1:]:
            if v.kind == "normalized:case":
                for h in self.find(v.text):
                    if h.value in seen_values or h.value in raw:
                        continue
                    seen_values.add(h.value)
                    findings.append(self._finding(segment, h, None, v.kind, "normalized"))
            elif v.kind.startswith("decoded:") and v.kind not in ("decoded:rot13", "decoded:reversed"):
                for h in self.find(v.text):
                    if h.value in seen_values or h.value in raw:
                        continue
                    seen_values.add(h.value)
                    findings.append(self._finding(segment, h, v.span, v.kind, "decoded"))
        return findings

    # ------------------------------------------------------------------ findings
    def _finding(self, segment: Segment, h: Hit, span: tuple[int, int] | None, view: str, how: str | None) -> Finding:
        action = self.actions.get(h.rule, self.default_action)
        title = next((r.title for r in RULES if r.id == h.rule), None) or {
            "password-assignment": "Password or API key assignment",
            "high-entropy-string": "High-entropy string that looks like a credential",
        }.get(h.rule, h.rule)
        title = title.split(" (")[0]
        where = WHERE.get(segment.direction, "in the text")
        token = f"[REDACTED:{h.rule}]"
        if span is None and action >= Action.REDACT:
            action = Action.BLOCK
        if how == "normalized":
            msg = (
                f"{title} {where} was found only after folding lookalike characters or joining split strings, so it "
                "cannot be redacted in place and the request was blocked. Remove the credential and rotate it if it was real."
            )
        else:
            prefix = f"{title} inside a {view.split(':', 1)[1]}-encoded blob {where}" if how == "decoded" else (
                f"{title} split across concatenated strings {where}" if how == "split" else f"{title} {where}"
            )
            if action == Action.REDACT:
                what = "the whole encoded blob was" if how == "decoded" else "it was"
                msg = f"{prefix}: {what} replaced with {token}. Credentials must not reach the model or logs; rotate it if it was real."
            elif action >= Action.REQUIRE_APPROVAL:
                verb = "blocked" if action == Action.BLOCK else "held for approval"
                msg = f"{prefix}: the request was {verb} (policy action for {h.rule} is {action.label}). Remove the credential and rotate it if it was real."
            else:
                msg = f"{prefix} was logged but not removed (policy action {action.label}). Credentials should not be sent to models; rotate it if it was real."
        return Finding(
            control=self.id,
            rule=h.rule,
            severity=h.severity,  # type: ignore[arg-type]
            action=action,
            message=msg,
            span=span,
            evidence=_evidence(h),
            owasp_llm=list(self.owasp_llm),
            owasp_agentic=list(self.owasp_agentic),
            atlas=list(ATLAS),
            view=view,
        )


def _evidence(h: Hit) -> str:
    v = h.value
    if h.rule == "private-key":
        first = v.splitlines()[0] if "\n" in v else v[:40]
        first = first.split("\\n")[0]
        return f"{first[:40]} ({len(v)} chars)"
    if len(v) <= 10:
        return mask(v, 1, 1)
    return mask(v, 4, 4)
