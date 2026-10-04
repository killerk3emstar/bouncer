"""Historical-attack signature control (control id "signatures").

A signature feed is a signed JSON document that lists known attack shapes (pickle RCE opcodes,
SSRF to cloud metadata, reverse shells, MCP tool poisoning, jailbreak families, ...). The feed is
managed outside the code base so the security team can add a signature and block a new attack
without a redeploy. The feed itself is an attack surface (supply chain), so it is signed with
ed25519 and an unsigned, tampered or malformed feed is rejected while the previous good version
stays active.

This module has two parts:

* ``FeedStore`` loads and verifies the feed, compiles the match patterns, keeps the last good
  version, refreshes it (local file mtime or an interval for an https:// feed), and reports status
  and per-signature hit counters for the dashboard (GET /api/signatures).
* ``SignaturesControl`` is a normal T0 ``Control``. For each segment it maps the segment direction
  to the signature targets, scans the raw, normalized and decoded views, decodes base64/hex blobs
  itself (a base64-wrapped pickle is binary, so ``normalize.prepare`` does not produce a decoded
  text view for it), and emits one finding per matching signature.

The store is injectable so the gateway can share one store across policy reloads (hit counters and
the last-good feed survive a reload): ``SignaturesControl(cfg, policy_doc, store=shared_store)``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from bouncer.core import Action, Control, Finding, Segment, View, mask
from bouncer.policy.schema import SignaturesCfg

log = logging.getLogger("bouncer.signatures")

CONTROL_ID = "signatures"

# Signature targets -> the Segment.direction they match. "tool_args" is the policy name for the
# JSON arguments of a tool call, which cross the gateway as direction "tool_call".
TARGET_TO_DIRECTION: dict[str, str] = {
    "input": "input",
    "output": "output",
    "tool_args": "tool_call",
    "tool_result": "tool_result",
    "tool_definition": "tool_definition",
}
VALID_TARGETS = set(TARGET_TO_DIRECTION)

MAX_SCAN_CHARS = 200_000
MAX_DECODE_BLOBS = 24
MAX_BLOB_CHARS = 262_144
MIN_BLOB_CHARS = 16
MAX_DECODED_BYTES = 262_144
_EVIDENCE_CHARS = 80

_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_RE_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL, "x": re.VERBOSE}

# Base64 / hex blob finders (binary-safe: we decode to bytes and scan as latin-1 so signatures can
# match pickle opcodes and other non-text payloads that normalize.prepare does not surface).
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_RE = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Za-z])")


# --------------------------------------------------------------------------- feed schema


class MatchModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    pattern: str | None = None
    flags: list[str] = []
    value: str | None = None
    values: list[str] = []
    threshold: int | None = Field(None, ge=1)
    of: str | None = None  # sha256 scope: "segment" (default) or "decoded"

    @field_validator("type")
    @classmethod
    def _known_type(cls, v: str) -> str:
        if v not in {"regex", "substring", "sha256", "structural"}:
            raise ValueError(f"unknown match type '{v}'")
        return v


class SignatureModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    description: str = ""
    targets: list[str]
    match: MatchModel
    decode: list[str] = []
    severity: str = "medium"
    action: str | None = None
    refs: list[str] = []
    cve: list[str] = []
    owasp_llm: list[str] = []
    owasp_agentic: list[str] = []
    atlas: list[str] = []
    added: str | None = None

    @field_validator("targets")
    @classmethod
    def _known_targets(cls, v: list[str]) -> list[str]:
        bad = [t for t in v if t not in VALID_TARGETS]
        if bad:
            raise ValueError(f"unknown target(s) {bad}; allowed: {sorted(VALID_TARGETS)}")
        if not v:
            raise ValueError("a signature must declare at least one target")
        return v

    @field_validator("severity")
    @classmethod
    def _known_severity(cls, v: str) -> str:
        if v not in _SEVERITIES:
            raise ValueError(f"unknown severity '{v}'")
        return v

    @field_validator("action")
    @classmethod
    def _known_action(cls, v: str | None) -> str | None:
        if v is not None:
            Action.parse(v)  # raises on unknown
        return v


class FeedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feed: str
    version: int
    updated: str
    signatures: list[SignatureModel]

    @field_validator("signatures")
    @classmethod
    def _unique_ids(cls, v: list[SignatureModel]) -> list[SignatureModel]:
        seen: set[str] = set()
        for s in v:
            if s.id in seen:
                raise ValueError(f"duplicate signature id '{s.id}'")
            seen.add(s.id)
        return v


# --------------------------------------------------------------------------- compiled signature


@dataclass
class CompiledSignature:
    model: SignatureModel
    directions: set[str]
    regex: re.Pattern[str] | None = None
    substrings: list[str] = field(default_factory=list)
    sha256_values: set[str] = field(default_factory=set)

    @property
    def id(self) -> str:
        return self.model.id


def _compile_signature(sig: SignatureModel) -> CompiledSignature:
    directions = {TARGET_TO_DIRECTION[t] for t in sig.targets}
    cs = CompiledSignature(model=sig, directions=directions)
    m = sig.match
    if m.type == "regex":
        if not m.pattern:
            raise ValueError(f"{sig.id}: regex match needs a pattern")
        flags = re.IGNORECASE  # feeds are case-insensitive by default; keyword attacks vary case
        for f in m.flags:
            if f not in _RE_FLAGS:
                raise ValueError(f"{sig.id}: unknown regex flag '{f}'")
            flags |= _RE_FLAGS[f]
        cs.regex = re.compile(m.pattern, flags)
    elif m.type == "substring":
        vals = ([m.value] if m.value else []) + list(m.values)
        if not vals:
            raise ValueError(f"{sig.id}: substring match needs value or values")
        cs.substrings = [v.lower() for v in vals]
    elif m.type == "sha256":
        vals = ([m.value] if m.value else []) + list(m.values)
        if not vals:
            raise ValueError(f"{sig.id}: sha256 match needs value or values")
        cs.sha256_values = {v.strip().lower() for v in vals}
    elif m.type == "structural":
        name = m.pattern or m.value
        if name != "many_shot":
            raise ValueError(f"{sig.id}: unknown structural matcher '{name}' (only 'many_shot')")
    return cs


# --------------------------------------------------------------------------- active feed


@dataclass
class ActiveFeed:
    model: FeedModel
    compiled: list[CompiledSignature]
    raw_sha256: str
    verified: bool
    loaded_at: float
    source: str

    @property
    def name(self) -> str:
        return self.model.feed

    @property
    def version(self) -> int:
        return self.model.version


# --------------------------------------------------------------------------- feed store


class FeedVerifyError(Exception):
    """A feed was missing, malformed, unsigned or had an invalid signature."""


class FeedStore:
    """Loads, verifies and holds the active signature feed. Thread-safe.

    A missing, malformed, unsigned (when required) or tampered feed never replaces a good one:
    ``last_error`` records why and the previous ``active`` feed keeps protecting traffic.
    """

    def __init__(
        self,
        feed: str = "signatures/feed.json",
        public_key: str | None = "signatures/feed.pub",
        require_signature: bool = True,
        refresh_seconds: int = 30,
        timeout_seconds: float = 3.0,
    ) -> None:
        self.feed = feed
        self.public_key_path = public_key
        self.require_signature = require_signature
        self.refresh_seconds = max(1, int(refresh_seconds))
        self.timeout_seconds = timeout_seconds
        self.is_url = feed.lower().startswith(("http://", "https://"))

        self._lock = threading.RLock()
        self.active: ActiveFeed | None = None
        self.last_error: str | None = None
        self.last_error_at: float | None = None
        self.last_check: float = 0.0
        self._last_mtime: float = 0.0
        self.hits: dict[str, dict[str, Any]] = {}  # signature id -> {count, last_hit, times}
        # audit hook, set by the gateway: on_event("feed.updated" | "feed.rejected", details)
        self.on_event: Any = None

        try:
            self._load()
        except FeedVerifyError as exc:
            self.last_error = str(exc)
            self.last_error_at = time.time()
            log.error("signature feed rejected at startup: %s", exc)

    # ---------------------------------------------------------------- loading

    def _read_public_key(self) -> bytes | None:
        if not self.public_key_path:
            return None
        raw = Path(self.public_key_path).read_text(encoding="utf-8").strip()
        try:
            key = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise FeedVerifyError(f"public key {self.public_key_path} is not valid base64: {exc}") from exc
        if len(key) != 32:
            raise FeedVerifyError(f"public key {self.public_key_path} must be 32 bytes, got {len(key)}")
        return key

    def _fetch(self) -> tuple[bytes, bytes | None, str]:
        """Return (feed bytes, signature bytes or None, source label)."""
        if self.is_url:
            import httpx

            with httpx.Client(timeout=self.timeout_seconds) as client:
                r = client.get(self.feed)
                r.raise_for_status()
                body = r.content
                sig = None
                try:
                    rs = client.get(self.feed + ".sig")
                    if rs.status_code == 200:
                        sig = rs.content
                except httpx.HTTPError:
                    sig = None
            return body, sig, self.feed
        path = Path(self.feed)
        body = path.read_bytes()
        sig_path = Path(self.feed + ".sig")
        sig = sig_path.read_bytes() if sig_path.exists() else None
        return body, sig, str(path)

    def _verify(self, body: bytes, sig_bytes: bytes | None) -> bool:
        """Verify the ed25519 signature over the exact feed bytes. Returns whether it was verified.

        Raises FeedVerifyError when require_signature is on and verification is not possible.
        """
        pub = self._read_public_key()
        if not self.require_signature:
            if sig_bytes is None or pub is None:
                return False
        if pub is None:
            raise FeedVerifyError("require_signature is on but no public_key is configured")
        if sig_bytes is None:
            raise FeedVerifyError("require_signature is on but the feed has no .sig file")
        try:
            sig = base64.b64decode(sig_bytes.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise FeedVerifyError(f"signature is not valid base64: {exc}") from exc

        try:
            from nacl.exceptions import BadSignatureError
            from nacl.signing import VerifyKey
        except ImportError as exc:  # pragma: no cover
            raise FeedVerifyError(f"PyNaCl is required to verify the feed: {exc}") from exc

        try:
            VerifyKey(pub).verify(body, sig)
        except BadSignatureError as exc:
            raise FeedVerifyError("signature does not match the feed bytes (tampered or wrong key)") from exc
        except ValueError as exc:
            raise FeedVerifyError(f"signature is malformed: {exc}") from exc
        return True

    def _load(self) -> bool:
        """Load, verify and compile the feed. Returns True if the active feed changed."""
        body, sig_bytes, source = self._fetch()
        raw_sha = hashlib.sha256(body).hexdigest()
        with self._lock:
            self.last_check = time.time()
            if self.active is not None and self.active.raw_sha256 == raw_sha and self.last_error is None:
                return False  # unchanged

        verified = self._verify(body, sig_bytes)

        try:
            model = FeedModel.model_validate_json(body)
        except ValidationError as exc:
            raise FeedVerifyError(f"feed does not match the schema: {exc.errors()[:3]}") from exc
        except ValueError as exc:
            raise FeedVerifyError(f"feed is not valid JSON: {exc}") from exc

        with self._lock:
            current = self.active
        if current is not None and model.feed == current.model.feed and model.version < current.model.version:
            # an older feed, even with a valid signature, would silently remove newer signatures
            raise FeedVerifyError(
                f"feed version {model.version} is older than the active version {current.model.version} (rollback refused)"
            )

        compiled: list[CompiledSignature] = []
        for sig in model.signatures:
            try:
                compiled.append(_compile_signature(sig))
            except (re.error, ValueError) as exc:
                raise FeedVerifyError(f"signature {sig.id} failed to compile: {exc}") from exc

        active = ActiveFeed(
            model=model,
            compiled=compiled,
            raw_sha256=raw_sha,
            verified=verified,
            loaded_at=time.time(),
            source=source,
        )
        with self._lock:
            previous = self.active
            self.active = active
            self.last_error = None
            for sig in compiled:
                self.hits.setdefault(sig.id, {"count": 0, "last_hit": None, "times": deque(maxlen=10_000)})
        log.info(
            "signature feed loaded: %s v%s (%d signatures, verified=%s)",
            model.feed,
            model.version,
            len(compiled),
            verified,
        )
        if previous is not None:
            self._emit("feed.updated", {
                "message": f"Signature feed {model.feed} updated from version {previous.model.version} to {model.version} "
                f"({len(previous.compiled)} -> {len(compiled)} signatures, signature {'verified' if verified else 'not verified'}).",
                "feed": {"name": model.feed, "from_version": previous.model.version, "to_version": model.version,
                         "signatures": len(compiled), "verified": verified, "sha256": raw_sha, "source": source},
            })
        return True

    def _emit(self, kind: str, data: dict[str, Any]) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(kind, data)
        except Exception:
            log.exception("could not record %s in the audit log", kind)

    def _rejected(self, error: str) -> None:
        """Record a rejected update once per distinct error (the same bad file is re-checked every refresh)."""
        with self._lock:
            repeat = error == self.last_error
            self.last_error = error
            self.last_error_at = time.time()
            active = self.active
        if repeat:
            return
        version = active.model.version if active else None
        self._emit("feed.rejected", {
            "message": f"Signature feed update rejected: {error}. The previous feed stays active"
            + (f" (version {version})." if version is not None else ".")
            + " Check the feed file and its .sig signature, then sign it again with make sign-feed.",
            "feed": {"name": active.model.feed if active else None, "active_version": version, "source": self.feed, "error": error},
        })

    # ---------------------------------------------------------------- refresh / status

    def maybe_refresh(self) -> bool:
        """Re-read the feed at most every refresh_seconds, and immediately when a local file's
        mtime changes. Returns True if the active feed changed. A bad update is rejected and the
        previous feed stays active (last_error is set)."""
        now = time.time()
        if not self.is_url:
            try:
                mtime = Path(self.feed).stat().st_mtime
            except OSError:
                mtime = 0.0
            due = mtime != self._last_mtime or (now - self.last_check) >= self.refresh_seconds
            if not due:
                return False
            self._last_mtime = mtime
        else:
            if (now - self.last_check) < self.refresh_seconds:
                return False
        try:
            return self._load()
        except FeedVerifyError as exc:
            self._rejected(str(exc))
            log.warning("signature feed update rejected, keeping previous version: %s", exc)
            return False
        except Exception as exc:  # network / IO
            self._rejected(f"{type(exc).__name__}: {exc}")
            self.last_check = now
            log.warning("signature feed refresh failed, keeping previous version: %s", exc)
            return False

    def record_hit(self, signature_id: str) -> None:
        with self._lock:
            h = self.hits.setdefault(signature_id, {"count": 0, "last_hit": None, "times": deque(maxlen=10_000)})
            now = time.time()
            h["count"] += 1
            h["last_hit"] = _iso(now)
            h["times"].append(now)

    def public_key_fingerprint(self) -> str | None:
        try:
            pub = self._read_public_key()
        except FeedVerifyError:
            return None
        if pub is None:
            return None
        return "ed25519:" + hashlib.sha256(pub).hexdigest()[:16]

    def status(self) -> dict[str, Any]:
        """Snapshot for GET /api/signatures: feed metadata plus a per-signature list with hits."""
        day_ago = time.time() - 86_400
        with self._lock:
            a = self.active
            sigs: list[dict[str, Any]] = []
            if a is not None:
                for cs in a.compiled:
                    s = cs.model
                    h = self.hits.get(s.id, {"count": 0, "last_hit": None, "times": ()})
                    sigs.append(
                        {
                            "id": s.id,
                            "title": s.title,
                            "description": s.description,
                            "targets": s.targets,
                            "match_type": s.match.type,
                            "severity": s.severity,
                            "action": s.action,
                            "decode": s.decode,
                            "cve": s.cve,
                            "refs": s.refs,
                            "owasp_llm": s.owasp_llm,
                            "owasp_agentic": s.owasp_agentic,
                            "atlas": s.atlas,
                            "added": s.added,
                            "hits_24h": sum(1 for t in h["times"] if t >= day_ago),
                            "hits_total": h["count"],
                            "last_hit": h["last_hit"],
                        }
                    )
            return {
                "feed": a.name if a else None,
                "version": a.version if a else None,
                "updated": a.model.updated if a else None,
                "source": self.feed,
                "sha256": a.raw_sha256 if a else None,
                "verified": a.verified if a else False,
                "require_signature": self.require_signature,
                "public_key_fingerprint": self.public_key_fingerprint(),
                "loaded_at": _iso(a.loaded_at) if a else None,
                "last_check": _iso(self.last_check) if self.last_check else None,
                "last_error": self.last_error,
                "last_error_at": _iso(self.last_error_at) if self.last_error and self.last_error_at else None,
                "signature_count": len(a.compiled) if a else 0,
                "signatures": sigs,
            }


def _iso(ts: float) -> str:
    """Unix seconds -> 2026-10-04T01:00:31.208Z, the timestamp format of the admin API."""
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- the control


class SignaturesControl(Control):
    id = CONTROL_ID
    owasp_llm = ["LLM01", "LLM03", "LLM05"]
    owasp_agentic = ["ASI04", "ASI05"]

    def __init__(self, cfg: SignaturesCfg, policy_doc: Any, store: FeedStore | None = None) -> None:
        super().__init__(cfg, policy_doc)
        self.default_action = cfg.action
        if store is None:
            store = FeedStore(
                feed=cfg.feed,
                public_key=cfg.public_key,
                require_signature=cfg.require_signature,
                refresh_seconds=cfg.refresh_seconds,
            )
        self.store = store

    def applies_to(self, segment: Segment) -> bool:
        # SignaturesCfg has no `directions`; a signature's own targets decide what it scans.
        return self.store.active is not None

    def maybe_refresh(self) -> bool:
        return self.store.maybe_refresh()

    def status(self) -> dict[str, Any]:
        return self.store.status()

    # ------------------------------------------------------------------ scanning

    def scan(self, segment: Segment, views: list[View], ctx: Any) -> list[Finding]:
        active = self.store.active
        if active is None:
            return []
        feed_name, feed_ver = active.name, active.version

        raw_view = next((v for v in views if v.kind == "raw"), None)
        raw_text = raw_view.text if raw_view is not None else (segment.text or "")
        text_views = [v for v in views if v.kind in ("raw", "normalized", "normalized:case")]
        if raw_view is None:
            text_views.insert(0, View(raw_text, "raw"))
        decoded_views = [v for v in views if v.kind.startswith("decoded:")]
        own_decoded: list[str] | None = None  # built lazily for decode-enabled signatures

        findings: list[Finding] = []
        for cs in active.compiled:
            if segment.direction not in cs.directions:
                continue
            finding: Finding | None = None
            mtype = cs.model.match.type

            if mtype == "structural":
                finding = self._match_structural(cs, raw_text, feed_name, feed_ver)
            elif mtype == "sha256":
                finding = self._match_sha256(cs, raw_text, feed_name, feed_ver)
                if finding is None and cs.model.decode:
                    if own_decoded is None:
                        own_decoded = self._decode_blobs(raw_text)
                    finding = self._match_sha256_decoded(cs, decoded_views, own_decoded, feed_name, feed_ver)
            else:
                # regex / substring: raw view first (for a span), then normalized views.
                for v in text_views:
                    hit = self._match_text(cs, v.text)
                    if hit is not None:
                        span = (hit[0], hit[1]) if v.kind == "raw" else None
                        finding = self._finding(cs, hit[2], feed_name, feed_ver, span=span, view=v.kind)
                        break
                if finding is None and cs.model.decode:
                    if own_decoded is None:
                        own_decoded = self._decode_blobs(raw_text)
                    candidates = [(dv.kind, dv.text) for dv in decoded_views] + [
                        ("decoded:bytes", b) for b in own_decoded
                    ]
                    for kind, dtext in candidates:
                        hit = self._match_text(cs, dtext)
                        if hit is not None:
                            finding = self._finding(cs, hit[2], feed_name, feed_ver, span=None, view=kind)
                            break

            if finding is not None:
                self.store.record_hit(cs.id)
                findings.append(finding)
        return findings

    def scan_text(self, text: str, direction: str) -> list[Finding]:
        """Scan a bare string (e.g. one tool-call argument) as a segment of `direction`.

        Convenience for callers that have text rather than a prepared Segment. Uses the raw text
        only plus the control's own base64/hex decoding; it does not run normalization.
        """
        seg = Segment(text or "", direction, f"{direction}:scan_text", trusted=False)
        return self.scan(seg, [View(text or "", "raw")], None)

    # ------------------------------------------------------------------ matchers

    @staticmethod
    def _match_text(cs: CompiledSignature, text: str) -> tuple[int, int, str] | None:
        if not text:
            return None
        scan = text[:MAX_SCAN_CHARS]
        if cs.regex is not None:
            m = cs.regex.search(scan)
            if m is not None:
                return m.start(), m.end(), m.group(0)
            return None
        if cs.substrings:
            low = scan.lower()
            for sub in cs.substrings:
                idx = low.find(sub)
                if idx >= 0:
                    return idx, idx + len(sub), scan[idx : idx + len(sub)]
        return None

    def _match_sha256(self, cs: CompiledSignature, text: str, feed: str, ver: int) -> Finding | None:
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        if digest in cs.sha256_values:
            return self._finding(cs, f"sha256={digest}", feed, ver, span=None, view="raw", evidence=digest)
        return None

    def _match_sha256_decoded(
        self, cs: CompiledSignature, decoded_views: list[View], own: list[str], feed: str, ver: int
    ) -> Finding | None:
        for text in [dv.text for dv in decoded_views] + own:
            digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
            if digest in cs.sha256_values:
                return self._finding(cs, f"sha256={digest}", feed, ver, span=None, view="decoded", evidence=digest)
        return None

    def _match_structural(self, cs: CompiledSignature, text: str, feed: str, ver: int) -> Finding | None:
        threshold = cs.model.match.threshold or 6
        turns = _count_dialogue_turns(text[:MAX_SCAN_CHARS])
        if turns >= threshold:
            return self._finding(
                cs,
                f"{turns} injected dialogue turns",
                feed,
                ver,
                span=None,
                view="raw",
                evidence=f"{turns} turns",
            )
        return None

    # ------------------------------------------------------------------ decoding

    def _decode_blobs(self, text: str) -> list[str]:
        """Decode base64/hex blobs in `text` to latin-1 strings so binary payloads (e.g. a pickle
        hidden in base64) can be scanned. normalize.prepare only surfaces blobs that look like text,
        so attack payloads that are mostly non-printable are decoded here instead."""
        out: list[str] = []
        scan = text[:MAX_SCAN_CHARS]
        for m in _B64_RE.finditer(scan):
            if len(out) >= MAX_DECODE_BLOBS:
                break
            blob = m.group(0)
            if len(blob) > MAX_BLOB_CHARS:
                continue
            dec = _b64_to_latin1(blob)
            if dec:
                out.append(dec)
        for m in _HEX_RE.finditer(scan):
            if len(out) >= MAX_DECODE_BLOBS:
                break
            blob = m.group(0)
            if len(blob) > MAX_BLOB_CHARS:
                continue
            try:
                raw = bytes.fromhex(blob)
            except ValueError:
                continue
            if len(raw) >= 4:
                out.append(raw[:MAX_DECODED_BYTES].decode("latin-1"))
        return out

    # ------------------------------------------------------------------ finding builder

    def _finding(
        self,
        cs: CompiledSignature,
        matched: str,
        feed: str,
        ver: int,
        *,
        span: tuple[int, int] | None,
        view: str,
        evidence: str | None = None,
    ) -> Finding:
        s = cs.model
        action = Action.parse(s.action) if s.action else Action.parse(self.default_action)
        remediation = s.description or "Block the request and investigate the source of this content."
        message = (
            f"{s.title}. Matched signature {s.id} from feed {feed} v{ver}. {remediation}"
        )
        ev = evidence if evidence is not None else _evidence(matched)
        return Finding(
            control=CONTROL_ID,
            rule=s.id,
            tier="T0",
            severity=s.severity,  # type: ignore[arg-type]
            action=action,
            score=1.0,
            message=message,
            span=span,
            evidence=ev,
            owasp_llm=list(s.owasp_llm),
            owasp_agentic=list(s.owasp_agentic),
            atlas=list(s.atlas),
            signature_id=s.id,
            view=view,
        )


# --------------------------------------------------------------------------- helpers

_DIALOGUE_RE = re.compile(
    r"^[ \t>*#-]*\"?(user|assistant|human|ai|system|q|a)\"?\s*[:\]]",
    re.IGNORECASE | re.MULTILINE,
)
_USER_ROLE = {"user", "human", "q"}
_ASSISTANT_ROLE = {"assistant", "ai", "a"}


def _count_dialogue_turns(text: str) -> int:
    """Count faux dialogue turns (many-shot jailbreak). Requires both user-side and assistant-side
    role labels so ordinary prose or a single transcript header does not trip it."""
    roles = [m.group(1).lower() for m in _DIALOGUE_RE.finditer(text)]
    if not roles:
        return 0
    users = sum(1 for r in roles if r in _USER_ROLE)
    assistants = sum(1 for r in roles if r in _ASSISTANT_ROLE)
    if users < 2 or assistants < 2:
        return 0
    return len(roles)


def _b64_to_latin1(blob: str) -> str | None:
    s = re.sub(r"\s+", "", blob).rstrip("=")
    if "-" in s or "_" in s:
        if "+" in s or "/" in s:
            return None
        s = s.replace("-", "+").replace("_", "/")
    if len(s) % 4 == 1 or len(s) < MIN_BLOB_CHARS:
        return None
    s += "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 4:
        return None
    return raw[:MAX_DECODED_BYTES].decode("latin-1")


def _evidence(matched: str) -> str:
    snippet = matched.replace("\n", "\\n").replace("\r", "")
    if len(snippet) > _EVIDENCE_CHARS:
        snippet = snippet[:_EVIDENCE_CHARS] + "..."
    return mask(snippet, keep_start=10, keep_end=6) if len(snippet) > 24 else snippet
