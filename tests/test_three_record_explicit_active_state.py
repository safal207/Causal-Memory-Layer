from __future__ import annotations

import pytest

from cml.three_record_audit import (
    FindingCode,
    audit_three_record_transition,
    wrap_record,
)


@pytest.mark.parametrize(
    "current_state",
    [
        pytest.param(None, id="missing"),
        pytest.param("", id="empty"),
        pytest.param("   ", id="whitespace"),
    ],
)
def test_allow_requires_explicit_active_state(current_state: str | None) -> None:
    authorization_record = {
        "transition_id": "transition-explicit-active",
        "subject_id": "agent:deploy",
        "action_identity_digest": "sha256:action-explicit-active",
        "binding_digest": "sha256:binding-explicit-active",
        "decision": "ALLOW",
        "causal_root": True,
    }
    if current_state is not None:
        authorization_record["current_state"] = current_state

    authorization = wrap_record(authorization_record)
    observation = wrap_record(
        {
            "transition_id": "transition-explicit-active",
            "subject_id": "agent:deploy",
            "authorization_ref": authorization["record_ref"],
            "action_identity_digest": "sha256:action-explicit-active",
            "binding_digest": "sha256:binding-explicit-active",
            "execution_status": "EXECUTED",
            "result_digest": "sha256:result-explicit-active",
        }
    )

    report = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=[observation],
        response_integrity_record=None,
    )

    assert [finding["code"] for finding in report["findings"]] == [
        FindingCode.OBSERVATION_WITHOUT_EXECUTABLE_AUTHORITY
    ]
    assert report["dimensions"]["authority"] == "UNKNOWN"
    assert report["dimensions"]["causal_validity"] == "INVALID"
    assert report["status"] == "FAILED"


def test_allow_with_explicit_active_state_remains_valid() -> None:
    authorization = wrap_record(
        {
            "transition_id": "transition-explicit-active",
            "subject_id": "agent:deploy",
            "action_identity_digest": "sha256:action-explicit-active",
            "binding_digest": "sha256:binding-explicit-active",
            "decision": "ALLOW",
            "current_state": "ACTIVE",
            "causal_root": True,
        }
    )
    observation = wrap_record(
        {
            "transition_id": "transition-explicit-active",
            "subject_id": "agent:deploy",
            "authorization_ref": authorization["record_ref"],
            "action_identity_digest": "sha256:action-explicit-active",
            "binding_digest": "sha256:binding-explicit-active",
            "execution_status": "EXECUTED",
            "result_digest": "sha256:result-explicit-active",
        }
    )

    report = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=[observation],
        response_integrity_record=None,
    )

    assert report["findings"] == []
    assert report["dimensions"]["authority"] == "VALID"
    assert report["dimensions"]["causal_validity"] == "VALID"
    assert report["status"] == "VERIFIED"
