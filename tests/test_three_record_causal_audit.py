import copy
import json
from pathlib import Path

import pytest

from cml.three_record_audit import (
    FindingCode,
    audit_three_record_transition,
    wrap_record,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATHS = [
    ROOT / "tests/fixtures/three_record_causal_audit_v0.1.json",
    ROOT / "tests/fixtures/three_record_causal_audit_edges_v0.1.json",
]


def load_cases() -> list[dict]:
    cases: list[dict] = []
    for path in FIXTURE_PATHS:
        fixture = json.loads(path.read_text(encoding="utf-8"))
        assert fixture["profile"] == "org.cml.three-record-causal-audit.v0.1"
        cases.extend(fixture["cases"])
    return cases


def materialize(case: dict) -> tuple[dict | None, list[dict], dict | None]:
    authorization_record = copy.deepcopy(case.get("authorization"))
    authorization = wrap_record(authorization_record) if authorization_record else None
    authorization_ref = authorization["record_ref"] if authorization else None

    observations: list[dict] = []
    observation_refs: dict[str, str] = {}
    for item in case.get("observations", []):
        record = copy.deepcopy(item["record"])
        if record.get("authorization_ref") == "$AUTHORIZATION_REF":
            record["authorization_ref"] = authorization_ref
        wrapper = wrap_record(record)
        observations.append(wrapper)
        observation_refs[item["key"]] = wrapper["record_ref"]

    integrity_record = copy.deepcopy(case.get("integrity"))
    integrity = None
    if integrity_record is not None:
        if integrity_record.get("authorization_ref") == "$AUTHORIZATION_REF":
            integrity_record["authorization_ref"] = authorization_ref

        integrity_record["observation_refs"] = [
            _replace_observation_reference(value, observation_refs)
            for value in integrity_record.get("observation_refs", [])
        ]
        for claim in integrity_record.get("claims", []):
            claim["observation_refs"] = [
                _replace_observation_reference(value, observation_refs)
                for value in claim.get("observation_refs", [])
            ]
        integrity = wrap_record(integrity_record)

    return authorization, observations, integrity


def _replace_observation_reference(value: str, references: dict[str, str]) -> str:
    prefix = "$OBSERVATION:"
    if value.startswith(prefix):
        key = value[len(prefix) :]
        return references[key]
    return value


@pytest.mark.parametrize("case", load_cases(), ids=lambda case: case["case_id"])
def test_three_record_causal_fixtures(case: dict) -> None:
    authorization, observations, integrity = materialize(case)

    first = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=observations,
        response_integrity_record=integrity,
    )
    second = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=observations,
        response_integrity_record=integrity,
    )

    assert second == first
    assert first["status"] == case["expected"]["status"]
    assert first["dimensions"] == case["expected"]["dimensions"]
    assert sorted({item["code"] for item in first["findings"]}) == sorted(
        case["expected"]["finding_codes"]
    )
    for finding in first["findings"]:
        assert finding["edge"]
        assert finding["record_ids"]
        assert finding["message"]


def test_response_integrity_failure_does_not_make_causal_chain_invalid() -> None:
    case = next(
        item for item in load_cases() if item["case_id"] == "valid_chain_contradicted_claim"
    )
    authorization, observations, integrity = materialize(case)

    report = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=observations,
        response_integrity_record=integrity,
    )

    assert report["dimensions"] == {
        "authority": "VALID",
        "execution": "OBSERVED_EXECUTED",
        "response_integrity": "FAILED",
        "causal_validity": "VALID",
    }
    assert report["findings"] == []


def test_consumed_authority_used_for_execution_emits_two_distinct_findings() -> None:
    authorization = wrap_record(
        {
            "transition_id": "transition-consumed",
            "subject_id": "agent:deploy",
            "action_identity_digest": "sha256:action-consumed",
            "binding_digest": "sha256:binding-consumed",
            "decision": "ALLOW",
            "current_state": "CONSUMED",
            "consumption_state": "CONSUMED",
            "causal_root": True,
        }
    )
    observation = wrap_record(
        {
            "transition_id": "transition-consumed",
            "subject_id": "agent:deploy",
            "authorization_ref": authorization["record_ref"],
            "action_identity_digest": "sha256:action-consumed",
            "binding_digest": "sha256:binding-consumed",
            "execution_status": "EXECUTED",
            "result_digest": "sha256:result-consumed",
        }
    )

    report = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=[observation],
        response_integrity_record=None,
    )

    codes = {item["code"] for item in report["findings"]}
    assert FindingCode.OBSERVATION_WITHOUT_EXECUTABLE_AUTHORITY in codes
    assert FindingCode.STALE_OR_CONSUMED_AUTHORITY_AS_LIVE in codes
    assert report["dimensions"]["authority"] == "CONSUMED"
    assert report["dimensions"]["execution"] == "OBSERVED_EXECUTED"
    assert report["dimensions"]["response_integrity"] == "NOT_EVALUATED"


def test_tampered_wrapper_is_reported_without_hiding_other_dimensions() -> None:
    case = next(item for item in load_cases() if item["case_id"] == "valid_supported_chain")
    authorization, observations, integrity = materialize(case)
    assert authorization is not None
    authorization["record_ref"] = "sha256:tampered"

    report = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=observations,
        response_integrity_record=integrity,
    )

    codes = {item["code"] for item in report["findings"]}
    assert FindingCode.RECORD_REFERENCE_MISMATCH in codes
    assert report["dimensions"]["authority"] == "VALID"
    assert report["dimensions"]["execution"] == "OBSERVED_EXECUTED"
    assert report["dimensions"]["response_integrity"] == "VERIFIED"
    assert report["dimensions"]["causal_validity"] == "INVALID"


def test_digest_only_records_do_not_require_sensitive_payloads() -> None:
    case = next(
        item for item in load_cases() if item["case_id"] == "digest_only_redacted_evidence"
    )
    authorization, observations, integrity = materialize(case)

    assert "arguments" not in authorization["record"]
    assert "result" not in observations[0]["record"]
    report = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=observations,
        response_integrity_record=integrity,
    )
    assert report["status"] == "VERIFIED"
    assert report["dimensions"]["causal_validity"] == "VALID"
