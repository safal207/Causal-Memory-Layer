from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "docs" / "outreach" / "owasp"


def test_crosswalk_covers_every_agent_safety_case_once() -> None:
    benchmark = json.loads((ROOT / "benchmarks" / "agent_safety" / "benchmark.json").read_text(encoding="utf-8"))
    crosswalk = json.loads((PACK / "crosswalk.json").read_text(encoding="utf-8"))

    benchmark_ids = [case["case_id"] for case in benchmark["scenarios"]]
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


def test_causal_space_time_map_preserves_organizational_boundaries() -> None:
    mapping = json.loads((PACK / "causal_space_time_map.json").read_text(encoding="utf-8"))
    nodes = {node["id"]: node for node in mapping["organizational_nodes"]}

    assert mapping["official_owasp_endorsement"] is False
    assert mapping["status"] == "proposed_navigation_model"
    assert mapping["verified_at"] == "2026-08-01"
    assert nodes["agentic-security-working-group"]["classification"] == "official_working_group"
    assert nodes["red-team-evaluation-initiative"]["classification"] == "official_initiative"
    assert nodes["mcp-security-workstream"]["classification"] == "documented_workstream"
    assert nodes["asi06-memory-guard"]["classification"] == "reference_implementation"
    assert nodes["agentic-security-working-group"]["channel"] == "#team-genai-agentic-security-initiative"
    assert nodes["red-team-evaluation-initiative"]["channel"] == "#team-genai-redteam"
    assert nodes["mcp-security-workstream"]["channel"] is None
    assert nodes["asi06-memory-guard"]["channel"] is None


def test_causal_space_time_map_uses_only_official_public_sources() -> None:
    mapping = json.loads((PACK / "causal_space_time_map.json").read_text(encoding="utf-8"))

    assert len(mapping["official_sources"]) >= 7
    for source in mapping["official_sources"]:
        parsed = urlparse(source["url"])
        assert parsed.scheme == "https"
        assert parsed.netloc in {"genai.owasp.org", "github.com"}
        if parsed.netloc == "github.com":
            assert parsed.path.startswith("/OWASP/")
        assert source["supports"]


def test_causal_space_time_map_defines_complete_guarded_lifecycle() -> None:
    mapping = json.loads((PACK / "causal_space_time_map.json").read_text(encoding="utf-8"))

    assert mapping["method"]["dimensions"] == ["cause", "space", "time", "transition"]
    assert [state["id"] for state in mapping["time_states"]] == [f"T{index}" for index in range(10)]
    assert len(mapping["spaces"]) == 7

    transitions = {(item["from"], item["to"]): item["guard"] for item in mapping["transitions"]}
    for edge in [
        ("T0", "T1"),
        ("T1", "T2"),
        ("T2", "T3"),
        ("T3", "T4"),
        ("T4", "T5"),
        ("T5", "T8"),
        ("T5", "T6"),
        ("T6", "T7"),
        ("T7", "T8"),
        ("T8", "T9"),
    ]:
        assert edge in transitions
        assert transitions[edge]


def test_owasp_entry_route_is_ordered_and_evidence_gated() -> None:
    mapping = json.loads((PACK / "causal_space_time_map.json").read_text(encoding="utf-8"))
    route = mapping["entry_route"]

    assert [step["order"] for step in route] == [1, 2, 3, 4]
    assert [step["target"] for step in route] == [
        "agentic-security-working-group",
        "red-team-evaluation-initiative",
        "mcp-security-workstream",
        "asi06-memory-guard",
    ]
    assert "five business days" in route[1]["trigger"]
    assert "ASB-12" in route[3]["trigger"]
    assert all(step["completion_evidence"] for step in route)


def test_workstream_messages_do_not_bypass_primary_submission() -> None:
    messages = (PACK / "WORKSTREAM_MESSAGES.md").read_text(encoding="utf-8")
    map_doc = (PACK / "CAUSAL_SPACE_TIME_MAP.md").read_text(encoding="utf-8")
    readme = (PACK / "README.md").read_text(encoding="utf-8")

    assert "Do not post all messages at once" in messages
    assert "#team-genai-redteam" in messages
    assert "No separate public MCP working-group channel is asserted" in messages
    assert "Do not approach Memory Guard until ASB-12 is executable" in messages
    assert "official OWASP hierarchy" in readme
    assert "T0 declared intent" in map_doc
    assert "T9 future session or reuse" in map_doc
