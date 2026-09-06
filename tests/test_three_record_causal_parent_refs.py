from __future__ import annotations

import pytest

from cml.three_record_audit import (
    FindingCode,
    ThreeRecordAuditError,
    audit_three_record_transition,
    wrap_record,
)


def _authorization(parent_refs: object) -> dict[str, object]:
    return wrap_record(
        {
            "transition_id": "transition-parent-refs",
            "subject_id": "agent:deploy",
            "action_identity_digest": "sha256:action-parent-refs",
            "binding_digest": "sha256:binding-parent-refs",
            "decision": "ALLOW",
            "current_state": "ACTIVE",
            "causal_parent_refs": parent_refs,
        }
    )


@pytest.mark.parametrize(
    "parent_refs",
    [
        pytest.param([""], id="empty"),
        pytest.param(["   "], id="whitespace"),
        pytest.param(["", "\t"], id="multiple-blank"),
    ],
)
def test_blank_parent_refs_do_not_establish_authorization_ancestry(
    parent_refs: list[str],
) -> None:
    report = audit_three_record_transition(
        authorization_record=_authorization(parent_refs),
        observation_records=[],
        response_integrity_record=None,
    )

    assert [finding["code"] for finding in report["findings"]] == [
        FindingCode.CAUSAL_CYCLE_OR_AMBIGUOUS_ROOT
    ]
    assert report["dimensions"]["causal_validity"] == "INVALID"
    assert report["status"] == "FAILED"


def test_valid_external_parent_survives_blank_noise() -> None:
    report = audit_three_record_transition(
        authorization_record=_authorization(
            ["sha256:external-parent", "", "   "]
        ),
        observation_records=[],
        response_integrity_record=None,
    )

    assert report["findings"] == []
    assert report["dimensions"]["causal_validity"] == "VALID"
    assert report["status"] == "VERIFIED"


def test_non_string_parent_ref_remains_a_structural_error() -> None:
    with pytest.raises(ThreeRecordAuditError, match="must be a string array"):
        audit_three_record_transition(
            authorization_record=_authorization(["sha256:external-parent", 7]),
            observation_records=[],
            response_integrity_record=None,
        )
