"""CrewAI-style three-record causal audit demo.

The example is framework-neutral and performs no real model or tool call. It
shows how an authorization provider, runtime observation, and post-response
claim verifier can be joined and audited by CML.
"""

from __future__ import annotations

import json

from cml.three_record_audit import audit_three_record_transition, wrap_record


def build_transition() -> tuple[dict, list[dict], dict]:
    authorization = wrap_record(
        {
            "transition_id": "crewai-transition-001",
            "subject_id": "agent:reporter",
            "action_identity_digest": "sha256:crewai-send-report-action",
            "binding_digest": "sha256:crewai-send-report-arguments",
            "decision": "ALLOW",
            "current_state": "ACTIVE",
            "causal_root": True,
            "policy_ref": "policy:external-report/v1",
        }
    )

    observation = wrap_record(
        {
            "transition_id": "crewai-transition-001",
            "subject_id": "agent:reporter",
            "authorization_ref": authorization["record_ref"],
            "action_identity_digest": "sha256:crewai-send-report-action",
            "binding_digest": "sha256:crewai-send-report-arguments",
            "execution_status": "EXECUTED",
            "result_digest": "sha256:redacted-runtime-result",
            "redaction_profile": "digest-only-v1",
        }
    )

    response_integrity = wrap_record(
        {
            "transition_id": "crewai-transition-001",
            "subject_id": "agent:reporter",
            "authorization_ref": authorization["record_ref"],
            "observation_refs": [observation["record_ref"]],
            "overall_verdict": "FAILED",
            "claims": [
                {
                    "claim_id": "claim-1",
                    "verdict": "CONTRADICTED",
                    "observation_refs": [observation["record_ref"]],
                }
            ],
        }
    )
    return authorization, [observation], response_integrity


def main() -> None:
    authorization, observations, integrity = build_transition()
    report = audit_three_record_transition(
        authorization_record=authorization,
        observation_records=observations,
        response_integrity_record=integrity,
    )

    print(json.dumps(report, indent=2, sort_keys=True))
    print("\nExpected independent dimensions:")
    print("- authority: VALID")
    print("- execution: OBSERVED_EXECUTED")
    print("- response_integrity: FAILED")
    print("- causal_validity: VALID")


if __name__ == "__main__":
    main()
