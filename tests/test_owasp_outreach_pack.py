from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "docs" / "outreach" / "owasp"


def test_crosswalk_covers_every_agent_safety_case_once() -> None:
    benchmark = json.loads((ROOT / "benchmarks" / "agent_safety" / "benchmark.json").read_text(encoding="utf-8"))
    crosswalk = json.loads((PACK / "crosswalk.json").read_text(encoding="utf-8"))

    benchmark_ids = [case["case_id"] for case in benchmark["cases"]]
    mapped_ids = [case["case_id"] for case in crosswalk["cases"]]

    assert mapped_ids == benchmark_ids
    assert len(mapped_ids) == len(set(mapped_ids)) == 10


def test_crosswalk_is_explicitly_proposed_and_records_gaps() -> None:
    crosswalk = json.loads((PACK / "crosswalk.json").read_text(encoding="utf-8"))

    assert crosswalk["official_owasp_mapping"] is False
    assert crosswalk["status"] == "proposed_for_community_review"
    assert crosswalk["taxonomy_coverage"]["ASI04"] == "gap"
    assert crosswalk["taxonomy_coverage"]["ASI05"] == "partial"
    assert crosswalk["taxonomy_coverage"]["ASI06"] == "partial"
    assert crosswalk["taxonomy_coverage"]["ASI10"] == "partial"

    proposed = {case["primary"] for case in crosswalk["proposed_v0_2_cases"]}
    assert proposed == {"ASI04", "ASI05", "ASI06", "ASI10"}


def test_submission_material_points_to_reviewable_evidence() -> None:
    slack = (PACK / "SLACK_MESSAGE.md").read_text(encoding="utf-8")
    brief = (PACK / "MEETING_BRIEF.md").read_text(encoding="utf-8")

    assert "#team-genai-agentic-security-initiative" in slack
    assert "benchmarks/agent_safety" in slack
    assert "trust-console/?evidence=mcp" in slack
    assert "does not claim OWASP endorsement" in slack
    assert "intent → causality → containment → recovery → independent verification" in brief
