"""Tool implementations, schemas, name mapping and web.fetch path handling."""

from __future__ import annotations

import json

import pytest

from demo import data, tools
from demo.naming import to_policy_name, to_wire_name


@pytest.fixture(autouse=True)
def _reset():
    tools.reset_state()
    yield
    tools.reset_state()


def _load(result: str) -> dict:
    return json.loads(result)


def test_naming_roundtrip():
    for policy in tools.TOOL_NAMES:
        wire = to_wire_name(policy)
        assert "." not in wire
        assert to_policy_name(wire) == policy
    # idempotent
    assert to_wire_name("crm__lookup_customer") == "crm__lookup_customer"
    assert to_policy_name("crm.lookup_customer") == "crm.lookup_customer"


def test_openai_schemas_valid_function_names():
    schemas = tools.openai_tools()
    assert len(schemas) == len(tools.TOOL_NAMES)
    import re

    for schema in schemas:
        name = schema["function"]["name"]
        assert re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name), name
        assert schema["function"]["parameters"]["type"] == "object"


def test_crm_lookup_by_id_and_name():
    out = _load(tools.run_tool("crm.lookup_customer", {"query": "C-10007"}))
    assert out["returned"] == 1
    assert out["customers"][0]["id"] == "C-10007"
    # accepts the wire name too
    out2 = _load(tools.run_tool("crm__lookup_customer", {"query": "C-10007"}))
    assert out2["customers"][0]["id"] == "C-10007"


def test_crm_lookup_wildcard_caps_results():
    out = _load(tools.run_tool("crm.lookup_customer", {"query": "*"}))
    assert out["total_matches"] == 50
    assert out["returned"] == tools.MAX_CUSTOMER_MATCHES == 10
    assert "note" in out


def test_crm_empty_query_is_error():
    out = _load(tools.run_tool("crm.lookup_customer", {"query": ""}))
    assert "error" in out


def test_kb_search_ranks_relevant_article():
    out = _load(tools.run_tool("kb.search", {"query": "rotate api keys secret"}))
    assert out["results"]
    assert out["results"][0]["id"] == "KB-006"


def test_kb_search_short_query_error():
    assert "error" in _load(tools.run_tool("kb.search", {"query": "a"}))


def test_web_fetch_maps_host_and_path():
    html = tools.run_tool("web.fetch", {"url": "https://vendor.example/pricing"})
    assert "<html" in html.lower()
    assert "pricing" in html.lower()


def test_web_fetch_index_fallback():
    html = tools.run_tool("web.fetch", {"url": "https://vendor.example"})
    assert "partner portal" in html.lower()


def test_web_fetch_unknown_is_404():
    out = tools.run_tool("web.fetch", {"url": "https://vendor.example/does-not-exist"})
    assert "404" in out


def test_web_fetch_rejects_traversal():
    out = tools.run_tool("web.fetch", {"url": "https://vendor.example/../../tools"})
    assert "404" in out  # resolved outside the host root -> not found


def test_web_fetch_unknown_host_is_404():
    out = tools.run_tool("web.fetch", {"url": "https://evil.example/pricing"})
    assert "404" in out


def test_web_fetch_rejects_non_http():
    out = _load(tools.run_tool("web.fetch", {"url": "file:///etc/passwd"}))
    assert "error" in out


def test_mail_send_appends_to_outbox():
    out = _load(tools.run_tool("mail.send", {"to": "a@bank.example", "subject": "s", "body": "b", "bcc": "x@evil.example"}))
    assert out["status"] == "queued"
    assert len(tools.OUTBOX) == 1
    assert tools.OUTBOX[0]["bcc"] == ["x@evil.example"]


def test_mail_send_requires_recipient():
    assert "error" in _load(tools.run_tool("mail.send", {"to": "", "subject": "s", "body": "b"}))
    assert not tools.OUTBOX


def test_payment_valid_iban():
    iban = data.get_customers()[0].iban
    out = _load(tools.run_tool("payments.create_transfer",
                               {"from_account": "x", "to_iban": iban, "amount": 100, "currency": "pln", "title": "t"}))
    assert out["status"] == "created"
    assert len(tools.TRANSFERS) == 1


def test_payment_rejects_bad_iban():
    out = _load(tools.run_tool("payments.create_transfer",
                               {"from_account": "x", "to_iban": "PL00", "amount": 100, "currency": "PLN", "title": "t"}))
    assert "error" in out
    assert not tools.TRANSFERS


def test_payment_rejects_bad_amount_and_currency():
    iban = data.get_customers()[0].iban
    assert "error" in _load(tools.run_tool("payments.create_transfer",
                                           {"from_account": "x", "to_iban": iban, "amount": -5, "currency": "PLN", "title": "t"}))
    assert "error" in _load(tools.run_tool("payments.create_transfer",
                                           {"from_account": "x", "to_iban": iban, "amount": 5, "currency": "XYZ", "title": "t"}))


def test_code_run_python_never_executes():
    out = _load(tools.run_tool("code.run_python", {"code": "print('should not run')"}))
    assert out["status"] == "not_executed"


def test_unknown_tool_and_bad_args():
    assert "error" in _load(tools.run_tool("does.not.exist", {}))
    assert "error" in _load(tools.run_tool("kb.search", {"query": "x", "extra": 1}))
    assert "error" in _load(tools.run_tool("kb.search", {}))  # missing required arg


def test_run_tool_accepts_json_string_arguments():
    out = _load(tools.run_tool("crm__lookup_customer", '{"query": "C-10002"}'))
    assert out["customers"][0]["id"] == "C-10002"
