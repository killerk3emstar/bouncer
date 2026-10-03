"""Loader and schema checks for demo/scenarios/*.yaml.

Scenario format (kind: openai, the default):

    id: s4-tool-loop                    # unique, also the file name
    title: ...                          # short, shown in the dashboard and summary table
    description: ...                    # one sentence: what Bouncer should do
    principal: ops-copilot              # key in policy/bouncer.yaml `principals`
    model: gpt-4o-mini                  # routed to the scripted mock upstream (:8702)
    tools: [kb.search, ...]             # policy names advertised to the model (OpenAI wire: dots -> "__")
    user: "..."                         # the user message
    system: "..."                       # optional, defaults to the agent's system prompt
    responses:                          # scripted model responses, one per model call, in order
      - content: "..."                  #   final answer
      - tool_calls:                     #   or tool calls (wire names, arguments as an object)
          - {name: kb__search, arguments: {query: fees}}
        usage: {prompt_tokens: 1, completion_tokens: 1}   # optional, reported by the mock
    expect:
      outcome: completed | blocked | approval_required | downgraded   # or a list of these
      code: ["loops.*"]                 # fnmatch patterns for the Bouncer error code (blocked/approval)
      stop_step: 4                      # model call (1-based) where the run ends; int or list
      steps:                            # optional per model call
        - {step: 1, action: allow}      #   X-Bouncer-Action; string or list
        - {step: 2, action: redact, findings: ["pii.*"], findings_any: [...]}
      upstream_must_not_contain:        # strings the mock upstream must never receive
        - AKIA...                       #   literal
        - {customer: C-10007, fields: [email, pesel]}   # values taken from demo/data.py
      answer_must_not_contain: [...]    # strings that must not be in the final answer
      outbox_must_be_empty: true        # mail.send must not have run

kind: mcp scenarios have `mcp_steps` instead of `user` / `responses`; see s8-mcp-rug-pull.yaml.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from demo import data
from demo.naming import to_policy_name
from demo.tools import TOOL_NAMES

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
OUTCOMES = {"completed", "blocked", "approval_required", "downgraded"}
ACTIONS = {"allow", "log", "redact", "block", "require_approval", "downgrade"}
MCP_STEP_KINDS = {"admin", "list_tools", "call_tool"}


class ScenarioError(ValueError):
    pass


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list | tuple) else [value]


def _check(cond: bool, sid: str, msg: str) -> None:
    if not cond:
        raise ScenarioError(f"{sid}: {msg}")


def validate(sc: dict[str, Any]) -> dict[str, Any]:
    sid = str(sc.get("id", "?"))
    for key in ("id", "title", "description", "principal", "expect"):
        _check(key in sc, sid, f"missing '{key}'")
    expect = sc["expect"]
    outcomes = as_list(expect.get("outcome"))
    _check(bool(outcomes) and set(outcomes) <= OUTCOMES, sid, f"expect.outcome must be in {sorted(OUTCOMES)}")
    kind = sc.get("kind", "openai")
    if kind == "mcp":
        steps = sc.get("mcp_steps")
        _check(isinstance(steps, list) and steps, sid, "mcp scenario needs mcp_steps")
        for st in steps:
            kinds = set(st) & MCP_STEP_KINDS
            _check(len(kinds) == 1, sid, f"mcp step needs exactly one of {sorted(MCP_STEP_KINDS)}: {st}")
        return sc
    _check(kind == "openai", sid, f"unknown kind {kind!r}")
    for key in ("model", "user", "responses", "tools"):
        _check(key in sc, sid, f"missing '{key}'")
    for tool in sc["tools"]:
        _check(to_policy_name(tool) in TOOL_NAMES, sid, f"unknown tool {tool!r}")
    responses = sc["responses"]
    _check(isinstance(responses, list) and responses, sid, "responses must be a non-empty list")
    for i, item in enumerate(responses, 1):
        _check(("content" in item) != ("tool_calls" in item), sid, f"response {i} needs content or tool_calls")
        for call in item.get("tool_calls", []):
            _check(to_policy_name(call.get("name", "")) in TOOL_NAMES, sid, f"response {i}: unknown tool {call}")
            _check(isinstance(call.get("arguments", {}), dict), sid, f"response {i}: arguments must be a mapping")
    for st in expect.get("steps", []):
        _check(isinstance(st.get("step"), int), sid, f"expect.steps entry without integer step: {st}")
        actions = as_list(st.get("action"))
        _check(set(actions) <= ACTIONS, sid, f"unknown action in {st}")
    for entry in expect.get("upstream_must_not_contain", []):
        if isinstance(entry, dict):
            _check(data.get_customer(entry.get("customer", "")) is not None, sid, f"unknown customer in {entry}")
    return sc


def forbidden_strings(entries: list[Any]) -> list[str]:
    """Expand upstream_must_not_contain entries into literal strings."""
    out: list[str] = []
    for entry in entries or []:
        if isinstance(entry, str):
            out.append(entry)
        elif isinstance(entry, dict):
            customer = data.get_customer(entry["customer"])
            if customer is None:
                raise ScenarioError(f"unknown customer {entry['customer']!r}")
            record = customer.to_dict()
            out.extend(str(record[f]) for f in entry.get("fields", []))
    return out


def load_scenarios(directory: Path = SCENARIO_DIR) -> list[dict[str, Any]]:
    scenarios = []
    for path in sorted(directory.glob("*.yaml")):
        sc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(sc, dict):
            raise ScenarioError(f"{path.name}: not a mapping")
        sc = validate(sc)
        if sc["id"] != path.stem:
            raise ScenarioError(f"{path.name}: id {sc['id']!r} must match the file name")
        scenarios.append(sc)
    return scenarios


def get_scenario(key: str, directory: Path = SCENARIO_DIR) -> dict[str, Any]:
    """Find a scenario by full id or by a unique prefix (s3 -> s3-indirect-injection-trifecta)."""
    scenarios = load_scenarios(directory)
    exact = [s for s in scenarios if s["id"] == key]
    if exact:
        return exact[0]
    prefixed = [s for s in scenarios if s["id"].startswith(key + "-") or s["id"].startswith(key)]
    if len(prefixed) == 1:
        return prefixed[0]
    # "s3" should pick s3-..., not s3b-...
    strict = [s for s in scenarios if s["id"].startswith(key + "-")]
    if len(strict) == 1:
        return strict[0]
    names = ", ".join(s["id"] for s in prefixed) or "none"
    raise ScenarioError(f"scenario {key!r} not found or ambiguous (matches: {names})")
