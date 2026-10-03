"""Container healthcheck: exit 0 when the URL answers HTTP 2xx within 3 seconds.

The slim Python image has no curl, so compose healthchecks call this instead:
    python docker/healthcheck.py http://127.0.0.1:8700/healthz
"""

from __future__ import annotations

import sys
import urllib.request


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8700/healthz"
    method = sys.argv[2] if len(sys.argv) > 2 else "GET"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method=method), timeout=3) as resp:  # noqa: S310 - local URL from compose
            return 0 if 200 <= resp.status < 300 else 1
    except Exception as exc:  # noqa: BLE001
        print(f"unhealthy: {url}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
