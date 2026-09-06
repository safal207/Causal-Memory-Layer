import copy
import json
from pathlib import Path

import pytest

from cml.three_record_audit import (
    FindingCode,
    ThreeRecordAuditError,
    _detect_cycle,
    audit_three_record_transition,
    canonical_json,
    wrap_record,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATHS = [
    ROOT / "tests/fixtures/three_record_causal_audit_v0.1.json",
    ROOT / "tests/fixtures/three_record_causal_audit_edges_v0.1.json",
]
_MISSING = object()


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
    if authorization is not None and case.get("authorization_record_ref"):
        authorization["record_ref"] = case["authorization_record_ref"]
    authorization_ref = authorization["record_ref"] if authorization else None

    observations: list[dict] = []
    observation_refs: dict[str, str] = {}
    for item in case.get("observations", []):
        record = copy.deepcopy(item["record"])
        if record.get("authorization_ref") == "$AUTHORIZATION_REF":
            record["authorization_ref"] = authorization_ref
        wrapper = wrap_record(record)
        if item.get("record_ref"):
            wrapper["record_ref"] = item["record_ref"]
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


def _valid_authorization_and_observation(
    *, field_name: str | None = None, replacement: object = _MISSING
) -> tuple[dict, dict]:
    authorization_record = {
        "transition_id": "transition-required-evidence",
        "subject_id": "agent:deploy",
        "action_identity_digest": "sha256:action-required-evidence",
        "binding_digest": "sha256:binding-required-evidence",
        "decision": "ALLOW",
        "current_state": "ACTIVE",
        "causal_root": True,
    }
    observation_record = {
        "transition_id": "transition-required-evidence",
        "subject_id": "agent:deploy",
        "action_identity_digest": "sha256:action-required-evidence",
        "binding_digest": "sha256:binding-required-evidence",
        "execution_status": "EXECUTED",
        "result_digest": "sha256:result-required-evidence",
    }
    if field_name is not None:
        if replacement is _MISSING:
            authorization_record.pop(field_name)
            observation_record.pop(field_name)
        else:
            authorization_record[field_name] = replacement
            observation_record[field_name] = replacement

    authorization = wrap_record(authorization_record)
    observation_record["authorization_ref"] = authorization["record_ref"]
    return authorization, wrap_record(observation_record)


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
        set(case["expected"]["finding_codes"])
    )

    finding_identities = [
        (item["code"], item["edge"], tuple(item["record_ids"]))
        for item in first["findings"]
    ]
    assert len(finding_identities) == len(set(finding_identities))
    assert first["summary"]["finding_count"] == len(finding_identities)

    for finding in first["findings"]:
        assert finding["edge"]
        assert finding["record_ids"]
        assert finding["message"]


@pytest.mark.parametrize("field_name", ["transition_id", "subject_id"])
@pytest.mark.parametrize(
    "replacement",
    [
        pytest.param(_MISSING, id="missing"),
        pytest.param("", id="empty"),
        pytest.param("   ", id="whitespace"),
    ],
)
def test_required_transition_and_subject_evidence_fail_closed(
    field_name: str, replacement: object
) -> None:
    authorization, observation = _valid_authorization_and_observation(
        field_name=field_name, replacement=replacement
    )

    report = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=[observation],
        response_integrity_record=None,
    )

    assert [item["code"] for item in report["findings"]] == [
        FindingCode.CROSS_SUBJECT_OR_TRANSITION_JOIN
    ]
    assert report["dimensions"]["causal_validity"] == "INVALID"


@pytest.mark.parametrize("field_name", ["action_identity_digest", "binding_digest"])
@pytest.mark.parametrize(
    "replacement",
    [
        pytest.param(_MISSING, id="missing"),
        pytest.param("", id="empty"),
        pytest.param("   ", id="whitespace"),
    ],
)
def test_required_action_and_binding_evidence_fail_closed(
    field_name: str, replacement: object
) -> None:
    authorization, observation = _valid_authorization_and_observation(
        field_name=field_name, replacement=replacement
    )

    report = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=[observation],
        response_integrity_record=None,
    )

    assert [item["code"] for item in report["findings"]] == [
        FindingCode.OBSERVATION_ACTION_BINDING_MISMATCH
    ]
    assert report["dimensions"]["causal_validity"] == "INVALID"


def test_missing_response_integrity_identity_cannot_join_by_none_equality() -> None:
    authorization, observation = _valid_authorization_and_observation()
    integrity = wrap_record(
        {
            "authorization_ref": authorization["record_ref"],
            "observation_refs": [observation["record_ref"]],
            "overall_verdict": "VERIFIED",
            "claims": [],
        }
    )

    report = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=[observation],
        response_integrity_record=integrity,
    )

    assert FindingCode.CROSS_SUBJECT_OR_TRANSITION_JOIN in {
        item["code"] for item in report["findings"]
    }
    assert report["dimensions"]["causal_validity"] == "INVALID"


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

    codes = [item["code"] for item in report["findings"]]
    assert codes.count(FindingCode.OBSERVATION_WITHOUT_EXECUTABLE_AUTHORITY) == 1
    assert codes.count(FindingCode.STALE_OR_CONSUMED_AUTHORITY_AS_LIVE) == 1
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


@pytest.mark.parametrize(
    "value",
    [
        {"bad": "surrogate-\ud800"},
        {"nested": ["valid", {"bad-key-\udfff": "value"}]},
    ],
)
def test_canonical_json_rejects_non_unicode_scalar_values(value: object) -> None:
    with pytest.raises(ThreeRecordAuditError, match="Unicode scalar values"):
        canonical_json(value)


def test_cycle_detection_handles_deep_lineage_without_recursion() -> None:
    depth = 2500
    graph = {"node-0000": set()}
    for index in range(1, depth):
        graph[f"node-{index:04d}"] = {f"node-{index - 1:04d}"}

    assert _detect_cycle(graph) is None

    graph["node-0000"] = {f"node-{depth - 1:04d}"}
    first = _detect_cycle(graph)
    second = _detect_cycle(graph)

    assert first == second
    assert first is not None
    assert first[0] == first[-1]
    assert len(first) == depth + 1
