from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "benchmarks" / "experimental" / "fcrp-self-006.json"
SOURCE = ROOT / "cml" / "experimental" / "focus_field.py"


def test_fcrp_self_006_identifies_temporal_contract_drift() -> None:
    case = json.loads(CASE.read_text(encoding="utf-8"))

    assert case["caseId"] == "FCRP-SELF-006"
    assert case["divergence"]["firstMeaningfulDivergence"] == "N1"
    assert case["divergence"]["causePoint"] == "N1"
    assert case["divergence"]["selectedRefactorPoint"] == "N4"
    assert case["navigation"]["direction"] == "UP"
    assert case["expectedProtocolDecision"] == "PASS"


def test_fcrp_self_006_refactor_uses_current_cml_gate_outputs() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    assert "verified: bool" not in source
    assert "ApplicabilityResult" in source
    assert "InformationQualityResult" in source
    assert "anchor.applicability.may_influence_action" in source
    assert "anchor.information_quality.ready_for_authority_check" in source
    assert 'state="reanchored_exploratory"' in source
    assert "trusted_continuation" in source
