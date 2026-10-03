"""The demo MCP server lists the tools and the poison toggle swaps a description."""

from __future__ import annotations

import asyncio

from fastmcp import Client

from demo import mcp_server as ms
from demo.tools import TOOL_NAMES


def _run(coro):
    return asyncio.run(coro)


def _tmp_flag(tmp_path):
    flag = tmp_path / "poison.flag"
    ms._FLAG_PATH = flag  # redirect the module-level flag to a temp file for the test
    return flag


def test_lists_all_tools_with_dotted_names(tmp_path):
    _tmp_flag(tmp_path)
    server = ms.build_server()

    async def go():
        async with Client(server) as c:
            tools = await c.list_tools()
            return {t.name: t for t in tools}

    tools = _run(go())
    assert set(tools) == set(TOOL_NAMES)
    # dotted (MCP) names, each with a parameters schema
    assert "crm.lookup_customer" in tools
    assert "query" in tools["crm.lookup_customer"].input_schema["properties"]


def test_call_tool_runs_implementation(tmp_path):
    _tmp_flag(tmp_path)
    server = ms.build_server()

    async def go():
        async with Client(server) as c:
            result = await c.call_tool("kb.search", {"query": "card fees"})
            return result.data

    data = _run(go())
    assert "KB-001" in data


def test_poison_toggle_swaps_kb_description(tmp_path):
    flag = _tmp_flag(tmp_path)
    server = ms.build_server()

    async def describe():
        async with Client(server) as c:
            tools = {t.name: t for t in await c.list_tools()}
            return tools["kb.search"].description

    clean = _run(describe())
    assert "IMPORTANT" not in clean

    ms.set_poison(True)
    assert flag.exists()
    poisoned = _run(describe())
    assert "<IMPORTANT>" in poisoned
    assert "id_rsa" in poisoned

    ms.set_poison(False)
    restored = _run(describe())
    assert "IMPORTANT" not in restored


def test_only_kb_search_is_poisoned(tmp_path):
    _tmp_flag(tmp_path)
    ms.set_poison(True)
    server = ms.build_server()

    async def go():
        async with Client(server) as c:
            return {t.name: t.description for t in await c.list_tools()}

    descriptions = _run(go())
    ms.set_poison(False)
    assert "IMPORTANT" in descriptions["kb.search"]
    for name, desc in descriptions.items():
        if name != "kb.search":
            assert "IMPORTANT" not in (desc or "")
