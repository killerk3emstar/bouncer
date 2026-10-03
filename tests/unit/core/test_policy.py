"""Policy engine mechanics: validation with line numbers, last-good-version on errors, hot reload,
profiles, history and diffs."""

from __future__ import annotations

import asyncio
import shutil
import time
from pathlib import Path

import pytest
import yaml

from bouncer.policy.loader import PolicyError, PolicyManager, parse_policy
from bouncer.policy.profiles import apply_profile

POLICY = Path("policy/bouncer.yaml")


@pytest.fixture()
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "bouncer.yaml"
    shutil.copy(POLICY, p)
    return p


def test_shipped_policy_is_valid() -> None:
    doc = parse_policy(POLICY.read_text())
    assert doc.profile == "balanced"
    assert doc.controls.secrets is not None and doc.controls.pii is not None


def test_yaml_syntax_error_has_line_number() -> None:
    text = POLICY.read_text().replace("profile: balanced", "profile: [balanced", 1)
    with pytest.raises(PolicyError) as exc:
        parse_policy(text)
    assert exc.value.line is not None and exc.value.line > 1


def test_schema_error_points_to_the_offending_line() -> None:
    text = POLICY.read_text()
    bad = text.replace("block_above: 0.98", "block_above: 1.7", 1)
    with pytest.raises(PolicyError) as exc:
        parse_policy(bad)
    expected_line = next(i for i, line in enumerate(bad.splitlines(), 1) if "1.7" in line)
    assert exc.value.line == expected_line
    assert "block_above" in exc.value.message


def test_unknown_key_is_rejected() -> None:
    text = POLICY.read_text().replace("  secrets:", "  secretz:", 1)
    with pytest.raises(PolicyError) as exc:
        parse_policy(text)
    assert "secretz" in exc.value.message


def test_bad_reference_is_rejected() -> None:
    text = POLICY.read_text().replace("downgrade_to: qwen3:8b", "downgrade_to: no-such-model", 1)
    with pytest.raises(PolicyError) as exc:
        parse_policy(text)
    assert "no-such-model" in exc.value.message


def test_external_judge_requires_opt_in() -> None:
    text = POLICY.read_text().replace("url: http://localhost:8701", "url: https://judge.example.com", 1)
    with pytest.raises(PolicyError) as exc:
        parse_policy(text)
    assert "allow_external" in exc.value.message


def test_invalid_reload_keeps_last_good_version(policy_file: Path) -> None:
    events = []
    mgr = PolicyManager(policy_file, on_event=lambda kind, data: events.append((kind, data)))
    first = mgr.load_initial()
    policy_file.write_text(policy_file.read_text().replace("version: 1", "version: [1", 1))
    assert mgr.reload() is False
    assert mgr.current.version == first.version
    assert mgr.last_error is not None and mgr.last_error["line"] is not None
    assert events and events[-1][0] == "policy.reload_failed"


def test_valid_reload_swaps_version_and_records_diff(policy_file: Path) -> None:
    events = []
    mgr = PolicyManager(policy_file, on_event=lambda kind, data: events.append((kind, data)))
    first = mgr.load_initial()
    policy_file.write_text(policy_file.read_text().replace("EMAIL: redact", "EMAIL: block", 1))
    assert mgr.reload() is True
    assert mgr.current.version != first.version
    assert mgr.current.doc.controls.pii.entities["EMAIL"] == "block"
    kind, data = events[-1]
    assert kind == "policy.reloaded"
    assert "-      EMAIL: redact" in data["diff"] and "+      EMAIL: block" in data["diff"]
    versions = mgr.versions()
    assert versions[0]["active"] and versions[0]["diff_from_previous"]


def test_removed_control_is_disabled(policy_file: Path) -> None:
    doc = yaml.safe_load(policy_file.read_text())
    del doc["controls"]["pii"]
    policy_file.write_text(yaml.safe_dump(doc, sort_keys=False))
    mgr = PolicyManager(policy_file)
    mgr.load_initial()
    assert mgr.current.doc.controls.pii is None
    assert "pii" not in mgr.current.variant().controls


def test_strict_profile_tightens_thresholds() -> None:
    doc = parse_policy(POLICY.read_text())
    strict = apply_profile(doc, "strict")
    assert strict.controls.prompt_injection.classifier.block_above <= 0.90
    assert strict.controls.prompt_injection.classifier.escalate_above <= 0.30
    assert strict.controls.pii.entities["NIP"] == "redact"
    assert strict.defaults.fail_mode == "closed"
    # the baseline is untouched
    assert doc.controls.prompt_injection.classifier.block_above == 0.98


def test_permissive_profile_fails_open() -> None:
    doc = parse_policy(POLICY.read_text())
    assert apply_profile(doc, "permissive").defaults.fail_mode == "open"


def test_watcher_reloads_within_two_seconds(policy_file: Path) -> None:
    async def run() -> float:
        mgr = PolicyManager(policy_file)
        first = mgr.load_initial().version
        task = asyncio.create_task(mgr.watch())
        await asyncio.sleep(0.3)
        t0 = time.perf_counter()
        policy_file.write_text(policy_file.read_text().replace("NIP: log", "NIP: redact", 1))
        while mgr.current.version == first and time.perf_counter() - t0 < 5:
            await asyncio.sleep(0.05)
        task.cancel()
        assert mgr.current.version != first, "watcher did not reload the policy"
        return time.perf_counter() - t0

    elapsed = asyncio.run(run())
    assert elapsed < 2.0
