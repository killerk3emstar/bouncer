# Signature feed

`feed.json` is the historical-attack signature feed. It lists known attack shapes (pickle RCE
opcodes, SSRF to cloud metadata, reverse shells, MCP tool poisoning, jailbreak families, ...) so the
security team can block a new attack by editing one signed file, with no code change and no restart.

The feed is loaded by `bouncer/controls/signatures.py` (`FeedStore` + `SignaturesControl`) and shown
in the dashboard at `GET /api/signatures`.

## Files

| File | Committed | What it is |
|---|---|---|
| `feed.json` | yes | the signatures (see format below) |
| `feed.json.sig` | yes | ed25519 signature over the exact bytes of `feed.json`, base64 |
| `feed.pub` | yes | ed25519 public key, base64; pinned in the policy (`controls.signatures.public_key`) |
| `../data/feed_signing.key` | no (gitignored) | ed25519 private seed, base64, chmod 600; demo key only |

## Trust model

The feed is itself a supply-chain target: anyone who can replace `feed.json` could disable a control
or whitelist an attack. So Bouncer verifies an ed25519 signature over the exact feed bytes against a
public key pinned in the policy, and **rejects** a feed that is missing, unsigned, tampered or
malformed — the previous good version keeps protecting traffic and the dashboard shows `last_error`.

- **In production** the private key lives with the feed publisher (CI signing step or an HSM), never
  in the repo. The gateway only ever holds the public key, pinned in `policy/bouncer.yaml`. A feed
  can then be served from a read-only URL (CDN, object store); see `scripts/feed_server.py` for the
  local demo of a remote feed URL.
- **In this repo** `data/feed_signing.key` is a throwaway demo key so the shipped feed is validly
  signed out of the box and the jury can re-sign after editing. It is gitignored. Treat it as public;
  do not reuse it anywhere real.

Rotating the key: delete `data/feed_signing.key`, run `make sign-feed` (or
`uv run python scripts/sign_feed.py`). A new key pair is generated, `feed.pub` is rewritten, and the
script prints the new fingerprint — pin it in the policy.

## Signing and refresh

```
uv run python scripts/sign_feed.py            # sign feed.json -> feed.json.sig
uv run python scripts/sign_feed.py --bump      # bump version + updated, then sign
uv run python scripts/sign_feed.py --check      # verify only (exit 1 on failure)
uv run python scripts/feed_server.py            # serve the feed on http://127.0.0.1:8704 (demo)
```

`SignaturesControl` re-reads the feed at most every `refresh_seconds` and immediately when the local
file's mtime changes (the gateway also calls `maybe_refresh()` about once a second and on file
changes under `signatures/`), so a re-signed feed is picked up without a restart.

## Feed format

```json
{
  "feed": "bouncer-community",
  "version": 1,
  "updated": "2026-10-04T00:00:00Z",
  "signatures": [
    {
      "id": "SIG-0004",
      "title": "Python pickle code-execution opcodes",
      "description": "What the attack does and what to do about it.",
      "targets": ["input", "tool_args", "tool_result"],
      "match": {"type": "regex", "pattern": "...", "flags": ["s"]},
      "decode": ["base64", "hex"],
      "severity": "critical",
      "action": "block",
      "refs": ["https://..."],
      "cve": [],
      "owasp_llm": ["LLM03"],
      "owasp_agentic": ["ASI05"],
      "atlas": ["AML.T0011.000"],
      "added": "2026-10-04"
    }
  ]
}
```

- **targets** — where the signature applies. These map to the segment direction the gateway sees:
  `input` (user/system/assistant text), `output` (model text), `tool_args` (tool-call arguments,
  direction `tool_call`), `tool_result` (tool output), `tool_definition` (tool name/description/schema).
- **match.type**
  - `regex` — Python `re` pattern. Case-insensitive by default; add more flags with
    `"flags": ["i","m","s","x"]`.
  - `substring` — `value` or `values` (case-insensitive).
  - `sha256` — `value`/`values` are hex digests of the whole segment text, or (with `decode`) of a
    decoded blob. Used for known-bad artifacts; `SIG-0020` ships the EICAR test digest.
  - `structural` — `pattern: "many_shot"` with `threshold` (N or more faux `User:`/`Assistant:`
    dialogue turns in one message).
- **decode** — also scan base64/hex blobs found in the text (decoded to raw bytes), so payloads that
  are not plain text — e.g. a pickle hidden in base64 — are matched. The control decodes these
  itself in addition to the decoded views that normalization produces.
- **action** — `allow` / `log` / `redact` / `require_approval` / `block`. Falls back to
  `controls.signatures.action` when omitted. **severity** — `info`/`low`/`medium`/`high`/`critical`.
- **refs / cve / owasp_llm / owasp_agentic / atlas** — provenance. Every CVE, OWASP id
  (LLM Top 10 2025, Agentic Top 10 2026) and MITRE ATLAS id in the shipped feed was verified against
  its primary source (NVD/CVE.org, the vendor advisory or the original research, and
  `mitre-atlas/atlas-data`). Keep it that way when adding signatures: no invented identifiers.

A signature fails the feed to load (so the previous version stays) if its regex does not compile, a
required field is missing, a target is unknown, or an id is duplicated.
