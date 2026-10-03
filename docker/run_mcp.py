"""Run the demo MCP server (demo/mcp_server.py) on a configurable host and port.

demo/mcp_server.py binds 127.0.0.1:8703, which is unreachable from other containers. This wrapper
builds the same server and binds MCP_HOST:MCP_PORT (defaults 0.0.0.0:8703) instead.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> None:
    from demo.mcp_server import build_server

    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_PORT", "8703"))
    build_server().run(transport="http", host=host, port=port)


if __name__ == "__main__":
    main()
