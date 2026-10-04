"""Every MITRE ATLAS id in the code, the signature feed, the docs and the dashboard fixtures exists in ATLAS.

atlas_techniques.json is the technique list of mitre-atlas/atlas-data dist/ATLAS.yaml (version and date inside);
refresh it from that file when ATLAS publishes a new version.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from bouncer.core import FINDING_ATLAS, Finding
from bouncer.policy.compiled import CONTROL_CATALOG

ROOT = Path(__file__).resolve().parents[3]
KNOWN = json.loads((Path(__file__).parent / "atlas_techniques.json").read_text())["techniques"]
ID = re.compile(r"AML\.T\d{4}(?:\.\d{3})?")


def _files() -> list[Path]:
    return (
        list((ROOT / "bouncer").rglob("*.py"))
        + list((ROOT / "bouncer" / "dashboard" / "fixtures").glob("*.json"))
        + list((ROOT / "docs").glob("*.md"))
        + [ROOT / "README.md", ROOT / "signatures" / "feed.json"]
    )


def test_every_atlas_id_exists() -> None:
    unknown = {(m, str(p.relative_to(ROOT))) for p in _files() for m in ID.findall(p.read_text(encoding="utf-8")) if m not in KNOWN}
    assert not unknown, f"ATLAS ids missing from atlas_techniques.json: {sorted(unknown)}"


def test_controls_and_findings_carry_atlas_ids() -> None:
    for cid, meta in CONTROL_CATALOG.items():
        if cid != "signatures":  # each signature carries its own ids
            assert meta.get("atlas"), cid
    assert Finding(control="loops", rule="identical_tool_calls").atlas == ["AML.T0034.002"]
    assert Finding(control="tool_governance", rule="lethal_trifecta").atlas[0] == "AML.T0086"
    assert Finding(control="tool_governance", rule="unknown_tool").atlas == ["AML.T0053"]
    assert Finding(control="mcp_pinning", rule="definition_changed").atlas == ["AML.T0109", "AML.T0110"]
    assert Finding(control="pii", rule="EMAIL", atlas=["AML.T0057"]).atlas == ["AML.T0057"]  # explicit ids win
    assert all(i in KNOWN for ids in FINDING_ATLAS.values() for i in ids)
