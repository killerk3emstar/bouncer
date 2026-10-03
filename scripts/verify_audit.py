"""Verify the hash chain of a Bouncer audit log.

Usage: uv run python scripts/verify_audit.py [data/audit.jsonl]
Exit code 0 when the chain is intact, 1 when a line was modified, deleted, inserted or reordered.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bouncer.audit import verify_file  # noqa: E402


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "data/audit.jsonl")
    if not path.exists():
        print(f"{path}: no audit log yet (start the gateway and send a request first)")
        return 1
    res = verify_file(path)
    if res["ok"]:
        print(f"{path}: OK, {res['checked']} lines, hash chain intact, last hash {res['last_hash'][:16]}...")
        return 0
    print(f"{path}: BROKEN at line {res['line']} (seq {res.get('seq')}): {res['error']}. {res['checked']} lines before it are intact.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
