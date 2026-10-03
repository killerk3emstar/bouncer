"""Scenario YAML files parse and only reference known tools and principals."""

from __future__ import annotations

from pathlib import Path

import yaml

from demo.naming import to_policy_name
from demo.scenario import SCENARIO_DIR, get_scenario, load_scenarios
from demo.tools import TOOL_NAMES

POLICY = Path(__file__).resolve().parents[3] / "policy" / "bouncer.yaml"


def _known_principals() -> set[str]:
    policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    return set(policy["principals"])


def test_scenarios_load():
    scenarios = load_scenarios()
    assert len(scenarios) >= 8
    ids = [s["id"] for s in scenarios]
    assert len(set(ids)) == len(ids)
    assert any(s["id"].startswith("s8") and s.get("kind") == "mcp" for s in scenarios)


def test_scenarios_cover_plan_numbers():
    ids = " ".join(s["id"] for s in load_scenarios())
    for prefix in ("s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"):
        assert prefix in ids, prefix


def test_principals_known():
    known = _known_principals()
    for sc in load_scenarios():
        assert sc["principal"] in known, f"{sc['id']}: unknown principal {sc['principal']}"


def test_tools_known():
    for sc in load_scenarios():
        for tool in sc.get("tools", []):
            assert to_policy_name(tool) in TOOL_NAMES, f"{sc['id']}: unknown tool {tool}"
        for item in sc.get("responses", []):
            for call in item.get("tool_calls", []):
                assert to_policy_name(call["name"]) in TOOL_NAMES


def test_scenario_tools_subset_of_principal_tools():
    policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    for sc in load_scenarios():
        if sc.get("kind") == "mcp":
            continue
        allowed = {to_policy_name(t) for t in policy["principals"][sc["principal"]]["tools"]}
        used = {to_policy_name(t) for t in sc.get("tools", [])}
        assert used <= allowed, f"{sc['id']}: advertises tools not granted to {sc['principal']}: {used - allowed}"


def test_scenario_models_known():
    policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    known_models = set(policy["models"])
    for sc in load_scenarios():
        if sc.get("kind") == "mcp":
            continue
        assert sc["model"] in known_models, f"{sc['id']}: unknown model {sc['model']}"
        allowed = set(policy["principals"][sc["principal"]]["models"])
        assert sc["model"] in allowed, f"{sc['id']}: model not allowed for principal"


def test_response_tool_calls_before_final_answer():
    # a scripted scenario should end with a final answer (content) unless it is blocked earlier
    for sc in load_scenarios():
        if sc.get("kind") == "mcp":
            continue
        assert any("content" in item for item in sc["responses"]), f"{sc['id']}: no final answer scripted"


def test_get_scenario_by_prefix():
    assert get_scenario("s3")["id"] == "s3-indirect-injection-trifecta"
    assert get_scenario("s3b")["id"] == "s3b-ascii-smuggling"
    assert get_scenario("s1")["id"] == "s1-customer-lookup"


def test_scenario_files_match_ids():
    for path in SCENARIO_DIR.glob("*.yaml"):
        sc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert sc["id"] == path.stem
