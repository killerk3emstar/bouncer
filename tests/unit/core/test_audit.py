"""Audit log hash chain: a modified, deleted or reordered line is detected."""

from __future__ import annotations

import json
from pathlib import Path

from bouncer.audit import AuditLog, to_csv, verify_file


def _write(path: Path, n: int = 5) -> AuditLog:
    log = AuditLog(path)
    for i in range(n):
        log.write({"kind": "decision", "trace_id": f"tr_{i}", "action": "allow", "findings": [], "excerpt": f"request {i}"})
    return log


def test_chain_verifies(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    _write(p)
    res = verify_file(p)
    assert res["ok"] and res["checked"] == 5


def test_modified_line_is_detected(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    _write(p)
    lines = p.read_text().splitlines()
    ev = json.loads(lines[2])
    ev["action"] = "block"
    lines[2] = json.dumps(ev)
    p.write_text("\n".join(lines) + "\n")
    res = verify_file(p)
    assert not res["ok"] and res["line"] == 3 and "modified" in res["error"]


def test_deleted_line_is_detected(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    _write(p)
    lines = p.read_text().splitlines()
    del lines[1]
    p.write_text("\n".join(lines) + "\n")
    res = verify_file(p)
    assert not res["ok"] and res["line"] == 2


def test_chain_resumes_after_restart(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    _write(p, 3)
    log2 = AuditLog(p)
    log2.write({"kind": "decision", "trace_id": "tr_after_restart", "action": "allow"})
    res = verify_file(p)
    assert res["ok"] and res["checked"] == 4
    assert log2.get("tr_after_restart")["seq"] == 4


def test_query_filters_and_csv(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    log.write({"kind": "decision", "trace_id": "a", "action": "block", "principal": {"id": "ops-copilot"}, "findings": [{"id": "secrets.jwt", "control": "secrets"}]})
    log.write({"kind": "decision", "trace_id": "b", "action": "allow", "principal": {"id": "dev-assistant"}, "findings": []})
    assert [e["trace_id"] for e in log.query(action="block")] == ["a"]
    assert [e["trace_id"] for e in log.query(control="secrets")] == ["a"]
    assert [e["trace_id"] for e in log.query(principal="dev-assistant")] == ["b"]
    csv_text = to_csv(log.query())
    assert csv_text.splitlines()[0].startswith("ts,seq,trace_id")
    assert "secrets.jwt" in csv_text
