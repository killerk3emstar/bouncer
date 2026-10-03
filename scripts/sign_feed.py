#!/usr/bin/env python3
"""Sign (or verify) the signature feed with an ed25519 key.

The feed is part of the supply chain, so Bouncer only loads a feed whose signature matches the
pinned public key. This script produces that signature.

Signature format: base64 of the 64-byte ed25519 signature over the EXACT bytes of
``signatures/feed.json`` (no re-serialization), written to ``signatures/feed.json.sig``.

Keys:
  * private key  ``data/feed_signing.key`` (base64 of the 32-byte seed; gitignored, chmod 600).
  * public key   ``signatures/feed.pub``   (base64 of the 32-byte verify key; committed, pinned in
    the policy via ``controls.signatures.public_key``).

If the private key is missing it is generated and the matching public key is written, with a clear
note that the public key changed (any previously signed feed must be re-signed).

Usage:
  uv run python scripts/sign_feed.py            # sign signatures/feed.json
  uv run python scripts/sign_feed.py --bump      # bump version + updated, then sign
  uv run python scripts/sign_feed.py --check      # verify the existing signature (exit 1 on failure)
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEED = ROOT / "signatures" / "feed.json"
SIG = ROOT / "signatures" / "feed.json.sig"
PUB = ROOT / "signatures" / "feed.pub"
KEY = ROOT / "data" / "feed_signing.key"


def _load_signing_key() -> tuple[SigningKey, bool]:  # noqa: F821
    from nacl.signing import SigningKey

    if KEY.exists():
        seed = base64.b64decode(KEY.read_text().strip(), validate=True)
        if len(seed) != 32:
            raise SystemExit(f"error: {KEY} is not a 32-byte ed25519 seed")
        return SigningKey(seed), False

    # Generate a new key pair.
    sk = SigningKey.generate()
    KEY.parent.mkdir(parents=True, exist_ok=True)
    KEY.write_text(base64.b64encode(bytes(sk)).decode() + "\n")
    KEY.chmod(0o600)
    return sk, True


def _write_public_key(sk: SigningKey) -> None:  # noqa: F821
    pub_b64 = base64.b64encode(bytes(sk.verify_key)).decode()
    PUB.write_text(pub_b64 + "\n")


def bump_version() -> None:
    data = json.loads(FEED.read_text())
    data["version"] = int(data.get("version", 0)) + 1
    data["updated"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    FEED.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n")
    print(f"bumped feed to version {data['version']} (updated {data['updated']})")


def sign() -> int:
    from nacl.signing import SigningKey  # noqa: F401  (import check)

    if not FEED.exists():
        print(f"error: {FEED} does not exist", file=sys.stderr)
        return 1
    sk, generated = _load_signing_key()
    if generated or not PUB.exists():
        _write_public_key(sk)
        print(
            f"note: wrote a new public key to {PUB.relative_to(ROOT)} "
            f"(fingerprint {_fingerprint(bytes(sk.verify_key))}). "
            "Pin it in policy controls.signatures.public_key; any earlier signature is now invalid."
        )
    body = FEED.read_bytes()
    signature = sk.sign(body).signature  # 64 bytes
    SIG.write_text(base64.b64encode(signature).decode() + "\n")
    print(f"signed {FEED.relative_to(ROOT)} -> {SIG.relative_to(ROOT)} ({len(body)} bytes)")
    return 0


def check() -> int:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    if not FEED.exists() or not SIG.exists() or not PUB.exists():
        print("error: feed, signature or public key is missing", file=sys.stderr)
        return 1
    pub = base64.b64decode(PUB.read_text().strip(), validate=True)
    sig = base64.b64decode(SIG.read_text().strip(), validate=True)
    body = FEED.read_bytes()
    try:
        VerifyKey(pub).verify(body, sig)
    except BadSignatureError:
        print("INVALID: signature does not match the feed (tampered or wrong key)", file=sys.stderr)
        return 1
    print(f"OK: signature valid for {FEED.relative_to(ROOT)} (key {_fingerprint(pub)})")
    return 0


def _fingerprint(pub: bytes) -> str:
    import hashlib

    return "ed25519:" + hashlib.sha256(pub).hexdigest()[:16]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Sign or verify signatures/feed.json (ed25519).")
    ap.add_argument("--check", action="store_true", help="verify the existing signature and exit")
    ap.add_argument("--bump", action="store_true", help="increment version and set updated before signing")
    args = ap.parse_args(argv)

    try:
        if args.check:
            return check()
        if args.bump:
            bump_version()
        return sign()
    except ImportError as exc:
        print(f"error: PyNaCl is required ({exc})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
