from __future__ import annotations

import pytest

from cml.three_record_audit import (
    FindingCode,
    audit_three_record_transition,
    wrap_record,
)


def _integrity(authorization_ref: object = "sha256:missing") -> dict[str, object]:
    record: dict[str, object] = {
        "transition_id": "transition-integrity-parent",
        "subject_id": "agent:report",
        "observation_refs": [],
        "overall_verdict": "VERIFIED",
        "claims": [],
    }
    if authorization_ref is not None:
        record["authorization_ref"] = authorization_ref
    return wrap_record(record)


@pytest.mark.parametrize(
    "authorization_ref",
    [
        pytest.param("sha256:missing", id="foreign-reference"),
        pytest.param(None, id="missing-reference"),
    ],
)
def test_integrity_without_supplied_authorization_fails_closed(
    authorization_ref: object,
) -> None:
    report = audit_three_record_transition(
        authorization_record=None,
        observation_records=[],
        response_integrity_record=_integrity(authorization_ref),
    )

    assert [finding["code"] for finding in report["findings"]] == [
        FindingCode.MISSING_AUTHORIZATION_PARENT
    ]
    assert report["dimensions"] == {
        "authority": "NOT_EVALUATED",
        "execution": "NOT_OBSERVED",
        "response_integrity": "VERIFIED",
        "causal_validity": "INVALID",
    }
    assert report["status"] == "FAILED"


def test_integrity_bound_to_supplied_authorization_has_no_missing_parent() -> None:
    authorization = wrap_record(
        {
            "transition_id": "transition-integrity-parent",
            "subject_id": "agent:report",
            "action_identity_digest": "sha256:action-integrity-parent",
            "binding_digest": "sha256:binding-integrity-parent",
            "decision": "ALLOW",
            "current_state": "ACTIVE",
            "causal_root": True,
        }
    )

    report = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=[],
        response_integrity_record=_integrity(authorization["record_ref"]),
    )

    assert FindingCode.MISSING_AUTHORIZATION_PARENT not in {
        finding["code"] for finding in report["findings"]
    }
    assert report["dimensions"]["causal_validity"] == "VALID"
    assert report["status"] == "VERIFIED"
