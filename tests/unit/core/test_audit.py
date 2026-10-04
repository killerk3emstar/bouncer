"""Audit log hash chain: a modified, deleted or reordered line is detected."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from bouncer.audit import CSV_FIELDS, AuditLog, event_epoch, to_csv, verify_file


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


def test_store_replays_todays_spend_from_audit(tmp_path: Path) -> None:
    from bouncer.store import Store

    log = AuditLog(tmp_path / "a.jsonl")
    log.write({"type": "decision", "trace_id": "a", "principal": {"id": "p", "team": "operations"}, "session_id": "s1", "usage": {"cost_usd": 0.25}})
    log.write({"type": "decision", "trace_id": "b", "principal": {"id": "p", "team": "operations"}, "session_id": "s1", "usage": {"cost_usd": 0.5}})
    store = Store()
    assert store.replay_spend(AuditLog(tmp_path / "a.jsonl").events) == 2
    assert abs(store.team_spend_today("operations") - 0.75) < 1e-9
    assert abs(store.sessions["s1"].usd - 0.75) < 1e-9


def test_trace_keeps_the_decision_first(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    log.write({"type": "decision", "trace_id": "tr_x", "action": "require_approval"})
    log.write({"type": "approval.decided", "trace_id": "tr_x", "decision": "approved"})
    assert log.get("tr_x")["type"] == "decision"
    assert [e["type"] for e in log.trace("tr_x")] == ["decision", "approval.decided"]
    resumed = AuditLog(tmp_path / "a.jsonl")
    assert resumed.get("tr_x")["action"] == "require_approval"


def test_csv_neutralizes_formulas(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    log.write({"type": "decision", "trace_id": "a", "action": "allow", "excerpt": "=HYPERLINK(\"http://x\",\"y\")"})
    assert "'=HYPERLINK" in to_csv(log.query())


def test_removed_tail_lines_are_detected(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    _write(p, 5)
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:3]) + "\n")
    res = verify_file(p)
    assert not res["ok"] and "removed from the end" in res["error"]


def test_export_reads_the_whole_file_oldest_first_with_unchanged_lines(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p, memory_size=3)  # the in-memory buffer keeps 3 events, the file has 8
    for i in range(8):
        log.write({"type": "decision", "trace_id": f"tr_{i}", "action": "block" if i % 2 else "allow", "findings": []})
    lines = [line for line, _ in log.export()]
    assert len(lines) == 8 and lines == p.read_text().splitlines(keepends=True)
    out = tmp_path / "export.jsonl"
    out.write_text("".join(lines))
    assert verify_file(out)["ok"]  # an unfiltered export verifies like the log itself
    assert [ev["trace_id"] for _, ev in log.export(action="block")] == ["tr_1", "tr_3", "tr_5", "tr_7"]


def test_export_time_window(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    for i, ts in enumerate(["2026-10-04T06:00:00.000Z", "2026-10-04T07:00:00.000Z", "2026-10-04T08:00:00.000Z"]):
        log.write({"ts": ts, "type": "decision", "trace_id": f"tr_{i}", "findings": []})
    since, until = event_epoch({"ts": "2026-10-04T06:30:00+00:00"}), event_epoch({"ts": "2026-10-04T07:30:00+00:00"})
    assert [ev["trace_id"] for _, ev in log.export(since_ts=since, until_ts=until)] == ["tr_1"]


def test_csv_has_the_contract_columns(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    log.write({
        "type": "decision", "trace_id": "a", "action": "block", "enforced": True, "status_code": 403,
        "principal": {"id": "ops-copilot", "team": "operations"}, "judge": {"invoked": False},
        "latency_ms": {"total": 5.0, "gateway_overhead": 4.0}, "findings": [
            {"id": "pii.EMAIL", "action": "redact", "severity": "medium", "score": 1.0, "owasp_llm": ["LLM02"]},
            {"id": "secrets.jwt", "action": "block", "severity": "high", "score": 0.9, "owasp_llm": ["LLM02"], "owasp_agentic": ["ASI03"]},
        ],
    })
    text = to_csv(log.query())
    assert "\r\n" in text
    rows = list(csv.DictReader(io.StringIO(text)))
    assert list(rows[0]) == CSV_FIELDS and len(CSV_FIELDS) == 26
    r = rows[0]
    assert r["top_finding"] == "secrets.jwt" and r["findings"] == "pii.EMAIL;secrets.jwt"
    assert r["owasp"] == "ASI03;LLM02" and r["enforced"] == "true" and r["judge_invoked"] == "false"
    assert r["team"] == "operations" and r["gateway_overhead_ms"] == "4.0" and r["approval_id"] == ""


def test_ocsf_detection_finding_mapping(tmp_path: Path) -> None:
    # OCSF 1.3.0 Detection Finding, security_control profile (validated with schema.ocsf.io/1.3.0/api/v2/validate)
    from bouncer.audit import to_ocsf

    log = AuditLog(tmp_path / "a.jsonl")
    ev = log.write({
        "type": "decision", "trace_id": "tr_1", "action": "redact", "principal": {"id": "ops-copilot", "team": "operations"},
        "findings": [{"id": "pii.EMAIL", "action": "redact", "severity": "medium", "score": 1.0, "owasp_llm": ["LLM02"], "atlas": ["AML.T0057"]}],
    })
    o = to_ocsf(ev)
    for key in ("activity_id", "category_uid", "class_uid", "finding_info", "metadata", "severity_id", "time", "type_uid", "action_id"):
        assert key in o
    assert (o["class_uid"], o["category_uid"], o["type_uid"], o["activity_id"]) == (2004, 2, 200401, 1)
    assert o["severity_id"] == 3 and o["action_id"] == 1 and o["disposition"] == "Redacted"
    assert o["finding_info"] == {"uid": "tr_1", "title": "pii.EMAIL", "types": ["pii.EMAIL"], "created_time": o["time"]}
    assert o["metadata"]["version"] == "1.3.0" and o["metadata"]["product"]["vendor_name"] == "Bouncer"
    assert o["unmapped"]["bouncer"]["mitre_atlas"] == ["AML.T0057"] and o["unmapped"]["bouncer"]["hash"] == ev["hash"]
    blocked = to_ocsf({**ev, "action": "block"})
    assert (blocked["action_id"], blocked["disposition_id"]) == (2, 2)
    held = to_ocsf({**ev, "action": "require_approval"})
    assert (held["action_id"], held["disposition_id"]) == (2, 14)
