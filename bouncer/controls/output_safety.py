"""Output safety (control id "output_safety"): what the model sends back to the client.

Rules:
  markdown-image  image ![..](url) (inline or reference-style) to a host outside allow_domains: rendering it
                  makes the client fetch the URL without a click, which carries data out (EchoLeak pattern).
  markdown-link   links [..](url), reference definitions, autolinks <https://...>, <a href> and bare URLs that
                  carry data, to hosts outside allow_domains; javascript:/vbscript: links always.
  html            <script>, <iframe>, <style>, <object>/<embed>/<form>/<meta>/<base>/<link>, <img> to foreign
                  hosts, inline event handlers (on*=) and javascript: URLs.
  canary          the canary token planted in the system prompt shows up in the output: the prompt leaked.

Markdown and HTML inside code fences or inline code are not rendered by clients, so they are skipped.
"""

from __future__ import annotations

import bisect
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from bouncer.core import Action, Control, Finding, ScanContext, Segment, View
from bouncer.policy.schema import OutputSafetyCfg

MAX_SCAN_CHARS = 200_000
ATLAS_EXFIL = ["AML.T0077", "AML.T0057"]  # LLM Response Rendering, LLM Data Leakage
ATLAS_CANARY = ["AML.T0056"]  # Extract LLM System Prompt (both verified in mitre-atlas/atlas-data)

_TITLE = r"(?:\s+(?:\"[^\"\n]*\"|'[^'\n]*'|\([^)\n]*\)))?"
_IMG_RE = re.compile(r"!\[(?P<alt>[^\]\n]{0,500})\]\(\s*<?(?P<url>[^)\s>]+)>?" + _TITLE + r"\s*\)")
_LINK_RE = re.compile(r"(?<!!)\[(?P<text>[^\]\n]{0,500})\]\(\s*<?(?P<url>[^)\s>]+)>?" + _TITLE + r"\s*\)")
_REFDEF_RE = re.compile(
    r"^ {0,3}\[(?P<label>[^\]\n]{1,200})\]:\s*<?(?P<url>[^\s>]+)>?" + _TITLE + r"[ \t]*$", re.MULTILINE
)
_REF_IMG_RE = re.compile(r"!\[(?P<alt>[^\]\n]{0,500})\](?:\[(?P<label>[^\]\n]{0,200})\])?")
_AUTOLINK_RE = re.compile(r"<(?P<url>(?:https?|ftp|mailto):[^\s<>]+)>", re.IGNORECASE)
_BARE_URL_RE = re.compile(r"(?<![\w(<\[=\"'/])(?P<url>https?://[^\s<>\"'\])]+)", re.IGNORECASE)
_A_TAG_RE = re.compile(r"<a\b[^>]*?\bhref\s*=\s*[\"']?(?P<url>[^\"'\s>]+)[^>]*>(?:[\s\S]{0,2000}?</a\s*>)?", re.IGNORECASE)

_HTML_RES: list[tuple[str, re.Pattern[str]]] = [
    ("script", re.compile(r"<script\b[^>]*>[\s\S]{0,20000}?(?:</script\s*>|\Z)|<script\b[^>]*/?>", re.IGNORECASE)),
    ("style", re.compile(r"<style\b[^>]*>[\s\S]{0,20000}?(?:</style\s*>|\Z)", re.IGNORECASE)),
    ("iframe", re.compile(r"<iframe\b[^>]*>(?:[\s\S]{0,20000}?</iframe\s*>)?", re.IGNORECASE)),
    ("embedded object", re.compile(r"<(?:object|embed|applet|frame|frameset|base|form|portal)\b[^>]*>", re.IGNORECASE)),
    ("meta/link", re.compile(r"<(?:meta|link)\b[^>]*>", re.IGNORECASE)),
    ("event handler", re.compile(r"<[a-z][a-z0-9-]*\b[^>]*?\son[a-z]{3,}\s*=[^>]*>", re.IGNORECASE)),
    ("script URL", re.compile(r"<[a-z][a-z0-9-]*\b[^>]*?\b(?:href|src|action|formaction|xlink:href|data)\s*=\s*[\"']?\s*"
                              r"(?:javascript|vbscript|data:text/html)[^>]*>", re.IGNORECASE)),
]
_IMG_TAG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_SRC_RE = re.compile(r"\b(?:src|srcset)\s*=\s*[\"']?(?P<url>[^\"'\s>]+)", re.IGNORECASE)

_FENCE_RE = re.compile(r"^ {0,3}(?P<f>`{3,}|~{3,})[^\n]*\n[\s\S]*?(?:^ {0,3}(?P=f)[ \t]*$|\Z)", re.MULTILINE)
_INLINE_CODE_RE = re.compile(r"(?<!`)(`+)(?!`)[^\n]+?(?<!`)\1(?!`)")
_DATAISH_RE = re.compile(r"[A-Za-z0-9+/=_%-]{16,}")


def _code_regions(text: str) -> list[tuple[int, int]]:
    if "`" not in text and "~~~" not in text:
        return []
    regions = [(m.start(), m.end()) for m in _FENCE_RE.finditer(text)]
    for m in _INLINE_CODE_RE.finditer(text):
        if not any(s <= m.start() < e for s, e in regions):
            regions.append((m.start(), m.end()))
    return sorted(regions)


def _in_regions(pos: int, regions: list[tuple[int, int]], starts: list[int]) -> bool:
    i = bisect.bisect_right(starts, pos) - 1
    return i >= 0 and regions[i][0] <= pos < regions[i][1]


def _carries_data(url: str) -> bool:
    """True when the URL looks like it carries data: long query values, long opaque path segments."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    for _, v in parse_qsl(parts.query, keep_blank_values=True):
        if len(v) >= 8:
            return True
    if len(parts.query) >= 24:
        return True
    for seg in parts.path.split("/"):
        if len(seg) >= 24 and _DATAISH_RE.search(seg):
            return True
    return len(parts.fragment) >= 16


def _carries_opaque_data(url: str) -> bool:
    """Stricter check for bare URLs: an opaque (encoded-looking) value, not a search phrase."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    for _, v in parse_qsl(parts.query, keep_blank_values=True):
        if len(v) >= 16 and " " not in v and _DATAISH_RE.fullmatch(v.replace("@", "").replace(".", "")):
            return True
    for seg in parts.path.split("/"):
        if len(seg) >= 24 and _DATAISH_RE.fullmatch(seg):
            return True
    return len(parts.query) >= 96


class OutputSafetyControl(Control):
    id = "output_safety"
    owasp_llm = ["LLM05", "LLM02"]
    owasp_agentic: list[str] = []

    def __init__(self, cfg: OutputSafetyCfg, policy_doc: Any = None) -> None:
        super().__init__(cfg, policy_doc)
        self.allow = tuple(d.lower().strip().strip(".") for d in cfg.markdown_links.allow_domains if d.strip())
        self.image_action = Action.parse(cfg.markdown_links.images)
        self.link_action = Action.parse(cfg.markdown_links.links)
        self.html_action: Action | None = {
            "strip": Action.REDACT,
            "block": Action.BLOCK,
            "log": Action.LOG,
            "allow": None,
        }[cfg.html]
        self.canary_action = Action.parse(cfg.canary.action) if cfg.canary.enabled else None

    # ------------------------------------------------------------------ helpers
    def host_allowed(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == d or host.endswith("." + d) for d in self.allow)

    def classify(self, url: str) -> tuple[str, str | None]:
        """('ok' | 'foreign' | 'script', host) for a URL found in markdown or HTML."""
        u = url.strip().strip("<>")
        low = unquote(u).lower().replace("\t", "").replace("\n", "").strip()
        if low.startswith(("javascript:", "vbscript:", "data:text/html")):
            return "script", None
        if low.startswith(("data:image/", "#", "tel:")):
            return "ok", None
        if low.startswith("mailto:"):
            addr = low[7:].split("?", 1)[0]
            host = addr.rsplit("@", 1)[-1] if "@" in addr else ""
            return ("ok" if host and self.host_allowed(host) else "foreign"), host or "a mail address"
        try:
            parts = urlsplit(u if "://" in u or u.startswith("//") else u)
            host = parts.hostname
        except ValueError:
            return "foreign", u[:40]
        if not host:
            if parts.scheme and parts.scheme not in ("http", "https"):
                return "foreign", parts.scheme + ":"
            return "ok", None  # relative URL: resolves against the page that renders it
        return ("ok" if self.host_allowed(host) else "foreign"), host

    # ------------------------------------------------------------------ scan
    def scan(self, segment: Segment, views: list[View], ctx: ScanContext) -> list[Finding]:
        raw = (views[0].text if views and views[0].kind == "raw" else segment.text)[:MAX_SCAN_CHARS]
        findings: list[Finding] = []
        if segment.direction == "output":
            findings.extend(self._markup(raw, segment))
        elif segment.direction == "tool_result" or (segment.direction == "input" and segment.role == "user"):
            findings.extend(self._inbound_images(raw, segment))
        canary = getattr(ctx, "canary", None) if ctx is not None else None
        if canary and self.canary_action is not None:
            f = self._canary(raw, views, canary, segment)
            if f is not None:
                findings.append(f)
        return findings

    def _inbound_images(self, text: str, segment: Segment) -> list[Finding]:
        """A markdown image that would send data to a foreign host, found before the model reads the text.

        In a tool result it is the EchoLeak setup (a page tells the model to render it), so it is removed before
        the model sees it. In a user message it is logged. Either way the model's answer is checked again."""
        if "](" not in text and "]:" not in text and "<img" not in text.lower():
            return []
        out = []
        for f in self._markup(text, segment):
            if f.rule != "markdown-image" or f.severity != "critical":
                continue  # only data-carrying images; links and HTML in inbound text are normal
            if segment.direction == "tool_result":
                f.action = Action.REDACT
                f.message = (
                    f"{f.message.split(' was removed from')[0].split(' is in the model')[0]} in {segment.source or 'a tool result'} "
                    "was removed before the model read it: content that asks the model to render an image with data in "
                    "its URL is the EchoLeak exfiltration pattern. The model's answer is checked again."
                )
            else:
                f.action = Action.LOG
                f.message = (
                    f"{f.message.split(' was removed from')[0].split(' is in the model')[0]} in the user message was logged; "
                    "if the model repeats it, it is removed from the answer (output_safety.markdown_links.images)."
                )
            out.append(f)
        return out

    def _markup(self, text: str, segment: Segment) -> list[Finding]:
        if "](" not in text and "<" not in text and "]:" not in text and "://" not in text:
            return []
        regions = _code_regions(text)
        starts = [s for s, _ in regions]
        out: list[Finding] = []
        covered: list[tuple[int, int]] = []

        def free(s: int, e: int) -> bool:
            return all(e <= a or s >= b for a, b in covered)

        def add(f: Finding | None, s: int, e: int) -> None:
            covered.append((s, e))
            if f is not None:
                out.append(f)

        # images first (zero-click)
        for m in _IMG_RE.finditer(text):
            if _in_regions(m.start(), regions, starts):
                continue
            kind, host = self.classify(m.group("url"))
            if kind != "ok":
                add(self._link_finding("markdown-image", m.group("url"), host, kind, (m.start(), m.end())), m.start(), m.end())
            else:
                covered.append((m.start(), m.end()))
        # reference definitions: an image if any image uses the label
        if "]:" in text:
            image_labels = set()
            for m in _REF_IMG_RE.finditer(text):
                label = (m.group("label") or m.group("alt") or "").strip().lower()
                if label:
                    image_labels.add(label)
            for m in _REFDEF_RE.finditer(text):
                if _in_regions(m.start(), regions, starts) or not free(m.start(), m.end()):
                    continue
                kind, host = self.classify(m.group("url"))
                if kind == "ok":
                    continue
                rule = "markdown-image" if m.group("label").strip().lower() in image_labels else "markdown-link"
                add(self._link_finding(rule, m.group("url"), host, kind, (m.start(), m.end())), m.start(), m.end())
        for m in _LINK_RE.finditer(text):
            if _in_regions(m.start(), regions, starts) or not free(m.start(), m.end()):
                continue
            kind, host = self.classify(m.group("url"))
            if kind != "ok":
                add(self._link_finding("markdown-link", m.group("url"), host, kind, (m.start(), m.end())), m.start(), m.end())
            else:
                covered.append((m.start(), m.end()))
        if "<" in text:
            for m in _AUTOLINK_RE.finditer(text):
                if _in_regions(m.start(), regions, starts) or not free(m.start(), m.end()):
                    continue
                kind, host = self.classify(m.group("url"))
                if kind != "ok":
                    add(self._link_finding("markdown-link", m.group("url"), host, kind, (m.start(), m.end())), m.start(), m.end())
            for m in _A_TAG_RE.finditer(text):
                if _in_regions(m.start(), regions, starts) or not free(m.start(), m.end()):
                    continue
                kind, host = self.classify(m.group("url"))
                if kind == "foreign":
                    add(self._link_finding("markdown-link", m.group("url"), host, kind, (m.start(), m.end())), m.start(), m.end())
            if self.html_action is not None:
                for label, rx in _HTML_RES:
                    for m in rx.finditer(text):
                        if _in_regions(m.start(), regions, starts) or not free(m.start(), m.end()):
                            continue
                        add(self._html_finding(label, m.group(0), (m.start(), m.end())), m.start(), m.end())
                for m in _IMG_TAG_RE.finditer(text):
                    if _in_regions(m.start(), regions, starts) or not free(m.start(), m.end()):
                        continue
                    srcs = [s.group("url") for s in _SRC_RE.finditer(m.group(0))]
                    bad = [(u, *self.classify(u)) for u in srcs]
                    bad = [b for b in bad if b[1] != "ok"]
                    if bad or not srcs:
                        u, kind, host = bad[0] if bad else ("", "foreign", None)
                        if kind == "foreign" and u:
                            add(self._link_finding("markdown-image", u, host, kind, (m.start(), m.end())), m.start(), m.end())
                        else:
                            add(self._html_finding("img", m.group(0), (m.start(), m.end())), m.start(), m.end())
        # bare URLs that carry data to a foreign host (clickable after GFM autolinking)
        if "://" in text:
            for m in _BARE_URL_RE.finditer(text):
                if _in_regions(m.start(), regions, starts) or not free(m.start(), m.end()):
                    continue
                url = m.group("url").rstrip(".,;:!?")
                kind, host = self.classify(url)
                if kind == "foreign" and _carries_opaque_data(url):
                    end = m.start() + len(url)
                    add(self._link_finding("markdown-link", url, host, kind, (m.start(), end), bare=True), m.start(), end)
        return out

    def _link_finding(
        self, rule: str, url: str, host: str | None, kind: str, span: tuple[int, int], bare: bool = False
    ) -> Finding:
        image = rule == "markdown-image"
        action = self.image_action if image else self.link_action
        data = _carries_data(url)
        if kind == "script":
            severity = "high"
            what = f"{'Image' if image else 'Link'} with a script URL ({url.split(':', 1)[0]}:)"
            why = "It runs code in the client when rendered or clicked."
        elif image:
            severity = "critical" if data else "high"
            what = f"Markdown image loading {host}"
            why = (
                "Rendering it makes the client fetch that URL without a click"
                + (", sending the data in the URL" if data else "")
                + " (zero-click exfiltration, the EchoLeak pattern)."
            )
        else:
            severity = "high" if data else "medium"
            what = f"{'URL' if bare else 'Link'} to {host}"
            why = (
                "Domains outside output_safety.markdown_links.allow_domains can receive data in the URL when it is clicked"
                + (" and this URL carries data in its query or path." if data else ".")
            )
        if action == Action.REDACT:
            verdict = "was removed from the model response"
        elif action == Action.BLOCK:
            verdict = "is in the model response, so the response was blocked"
        elif action == Action.REQUIRE_APPROVAL:
            verdict = "is in the model response and needs approval"
        else:
            verdict = "is in the model response (logged)"
        advice = "" if kind == "script" else " Add the domain to allow_domains only if it is trusted."
        return Finding(
            control=self.id,
            rule=rule,
            severity=severity,  # type: ignore[arg-type]
            action=action,
            message=f"{what} {verdict}. {why}{advice}",
            span=span,
            evidence=_short(_mask_query(url), 80),
            owasp_llm=["LLM05", "LLM02"],
            owasp_agentic=[],
            atlas=list(ATLAS_EXFIL),
            view="raw",
        )

    def _html_finding(self, label: str, element: str, span: tuple[int, int]) -> Finding:
        action = self.html_action or Action.LOG
        verdict = {
            Action.REDACT: "was removed from the model response",
            Action.BLOCK: "is in the model response, so the response was blocked",
            Action.LOG: "is in the model response (logged)",
        }.get(action, "is in the model response")
        severity = "high" if label in ("script", "event handler", "script URL", "iframe") else "medium"
        return Finding(
            control=self.id,
            rule="html",
            severity=severity,  # type: ignore[arg-type]
            action=action,
            message=(
                f"HTML {label} element {verdict}. Raw HTML in model output can run script or load "
                "remote content in the client (insecure output handling); render model output as text or escape it."
            ),
            span=span,
            evidence=_short(_mask_query(element), 80),
            owasp_llm=["LLM05"],
            owasp_agentic=[],
            atlas=[],
            view="raw",
        )

    def _canary(self, raw: str, views: list[View], canary: str, segment: Segment) -> Finding | None:
        span = None
        view = None
        idx = raw.find(canary)
        if idx >= 0:
            span = (idx, idx + len(canary))
            view = "raw"
        else:
            key = re.sub(r"[\W_]+", "", canary.casefold())
            if key and key in re.sub(r"[\W_]+", "", raw.casefold()):
                view = "normalized"
            else:
                for v in views[1:]:
                    if v.kind.startswith("decoded:") and key in re.sub(r"[\W_]+", "", v.text.casefold()):
                        view = v.kind
                        span = v.span
                        break
        if view is None:
            return None
        action = self.canary_action or Action.BLOCK
        if span is None and action == Action.REDACT:
            action = Action.BLOCK
        where = {"output": "model response", "tool_call": "tool call arguments"}.get(segment.direction, segment.direction)
        how = "" if view == "raw" else f" (found after {'removing separators' if view == 'normalized' else 'decoding ' + view.split(':', 1)[1]})"
        verdict = {
            Action.BLOCK: "The response was blocked",
            Action.REDACT: "The token was removed",
            Action.REQUIRE_APPROVAL: "The response needs approval",
        }.get(action, "This was logged")
        return Finding(
            control=self.id,
            rule="canary",
            severity="critical",
            action=action,
            message=(
                f"The canary token planted in the system prompt appeared in the {where}{how}: the system prompt "
                f"leaked. {verdict}; look for a prompt extraction attempt earlier in this session."
            ),
            span=span,
            evidence=_short(canary[:4] + "***", 20),
            owasp_llm=["LLM07"],
            owasp_agentic=[],
            atlas=list(ATLAS_CANARY),
            view=view,
        )


def _mask_query(text: str) -> str:
    """Evidence must not carry the data an exfiltration URL smuggles: keep scheme, host and path, mask the
    query string and fragment."""
    return re.sub(r"([?#])[^\s\"'<>)]*", r"\1[masked]", text)


def _short(s: str, n: int) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."
