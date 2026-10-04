"""MCP gateway checks: audit excerpt of a blocked tool result, non-text content blocks in results.

Run: PYTHONPATH=.:scripts/secreview uv run python scripts/secreview/mcp_checks.py
Starts the gateway with uvicorn on 8705/8706 (or an ephemeral port) in a thread and stops it at the end.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path

import harness  # noqa: F401  (chdir + env)
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from mcp.types import EmbeddedResource, TextResourceContents

from bouncer.gateway.app import create_app
from bouncer.gateway.state import Settings
from tests.unit.mcp.test_mcp_gateway import _Server

CARD = harness.CARD
KEY = harness.OPS


def upstream() -> FastMCP:
    srv = FastMCP("demo-bank")

    @srv.tool(name="crm.lookup_customer")
    def lookup(customer_id: str) -> str:
        """Look up a customer record."""
        return f"Customer {customer_id}: card {CARD}"

    @srv.tool(name="kb.search")
    def kb(query: str) -> list:
        """Search the knowledge base."""
        return [EmbeddedResource(type="resource", resource=TextResourceContents(uri="kb://doc/1", mimeType="text/plain", text=f"Doc text. Service key {harness.AWS}. card {CARD}"))]

    return srv


async def call(url: str, name: str, args: dict) -> object:
    async with Client(StreamableHttpTransport(url + "/mcp", headers={"X-Bouncer-Session": "mcp-rev"}, auth=KEY)) as c:
        await c.list_tools()
        return await c.call_tool_mcp(name, args)


def main() -> None:
    os.environ.update(harness.KEYS)
    tmp = Path(tempfile.mkdtemp(prefix="secrev_mcp_"))
    policy = tmp / "bouncer.yaml"
    shutil.copy("policy/bouncer.yaml", policy)
    audit = tmp / "audit.jsonl"
    app = create_app(Settings(policy_path=str(policy), audit_path=str(audit), t1="fake", judge_override="fake", watch=False))
    app.state.mcp.set_upstream(upstream())
    try:
        with _Server(app) as srv:
            r = asyncio.run(call(srv.url, "crm.lookup_customer", {"customer_id": "C-1001"}))
            ev = [json.loads(x) for x in audit.read_text().splitlines() if '"mcp.call"' in x][-1]
            print("crm.lookup_customer -> isError", r.isError, "| action", ev["action"], "| findings", [f["id"] for f in ev["findings"]])
            print("  audit excerpt:", ev["excerpt"])
            r = asyncio.run(call(srv.url, "kb.search", {"query": "fees"}))
            ev = [json.loads(x) for x in audit.read_text().splitlines() if '"mcp.call"' in x][-1]
            blocks = [b.model_dump() for b in r.content]
            print("kb.search (embedded resource) -> isError", r.isError, "| action", ev["action"], "| findings", [f["id"] for f in ev["findings"]])
            print("  client received raw card:", CARD in json.dumps(blocks), "| raw key:", harness.AWS in json.dumps(blocks))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
