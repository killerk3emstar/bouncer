#!/usr/bin/env python3
"""Serve the signature feed over HTTP for the "remote feed URL" demo.

Bouncer can load its feed from a local path or an https:// URL. This tiny server publishes
``signatures/feed.json`` and ``signatures/feed.json.sig`` (and ``feed.pub``) on
http://127.0.0.1:8704 so the gateway can be pointed at a remote feed and pick up a re-signed
update without a restart.

It serves only those three files (read-only GET/HEAD); everything else is 404. For the demo only;
a real publisher serves the signed feed from a CDN or object store.

Usage:
  uv run python scripts/feed_server.py                 # 127.0.0.1:8704
  uv run python scripts/feed_server.py --port 8704
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIG_DIR = ROOT / "signatures"

ALLOWED = {
    "/feed.json": ("feed.json", "application/json"),
    "/feed.json.sig": ("feed.json.sig", "text/plain"),
    "/feed.pub": ("feed.pub", "text/plain"),
}


class FeedHandler(BaseHTTPRequestHandler):
    server_version = "BouncerFeed/0.1"

    def _serve(self, body_only: bool) -> None:
        entry = ALLOWED.get(self.path.split("?", 1)[0])
        if entry is None:
            self.send_error(404, "not found (only /feed.json, /feed.json.sig, /feed.pub)")
            return
        name, content_type = entry
        path = SIG_DIR / name
        if not path.exists():
            self.send_error(404, f"{name} not found")
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if not body_only:
            self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        self._serve(body_only=False)

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(body_only=True)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[feed] {self.address_string()} {fmt % args}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Serve the signed signature feed over HTTP (demo).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8704)
    args = ap.parse_args(argv)

    httpd = ThreadingHTTPServer((args.host, args.port), FeedHandler)
    print(f"serving {SIG_DIR} on http://{args.host}:{args.port}/feed.json  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
