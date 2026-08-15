from __future__ import annotations

import copy
import unittest

from cml.experimental.memory_proposal_queue_planner import plan
from cml.experimental.memory_proposal_queue_revalidation import build_planner_record
from cml.experimental.memory_proposal_semantic_acceptance import (
    SemanticAcceptanceError,
    build_semantic_acceptance_intake,
    validate_human_submission,
)


PACK = "a" * 64
REPLAY = "b" * 64
SOURCE_CORE = "c" * 64
SOURCE_CORE_DRIFT = "d" * 64
SOURCE = "1" * 40
MAIN = "2" * 40
AUDIT = "sha256:" + "e" * 64


class MemoryProposalSemanticAcceptanceTests(unittest.TestCase):
    def observation(self):
        return {
            "repository": "safal207/Causal-Memory-Layer",
            "proposal_pr": 191,
            "source_pr": 190,
            "source_merge": SOURCE,
            "current_main_revision": MAIN,
            "pack_id": PACK,
            "validated_pack_id": PACK,
            "replayed_pack_id": REPLAY,
            "expected_source_core_digest": SOURCE_CORE,
            "observed_source_core_digest": SOURCE_CORE,
            "full_pack_replay_match": False,
            "changed_evidence_components": ["source-pr", "source-checks"],
            "self_observation_completion_drift": False,
            "source_exists": True,
            "source_ancestor_of_main": True,
            "evidence_refs": [
                "https://github.com/safal207/Causal-Memory-Layer/pull/191",
                "https://github.com/safal207/Causal-Memory-Layer/pull/190",
            ],
        }

    def planner_pair(self, observation=None):
        record = build_planner_record(observation or self.observation())
        planner_input = {
            "schema": "cml.memory-proposal-queue.revalidation-input.v0.2",
            "source_audit_schema": "cml.memory-proposal-queue.audit.v0.1",
            "source_audit_digest": AUDIT,
            "current_main_revision": record["revalidation"].get(
                "current_main_revision", MAIN
            ),
            "captured_at": "2026-08-15T14:22:27Z",
            "synthetic": True,
            "expected_record_count": 1,
            "records": [record],
        }
        # build_planner_record does not duplicate current_main_revision at top level.
        planner_input["current_main_revision"] = (
            observation or self.observation()
        )["current_main_revision"]
        return planner_input, plan(planner_input)

    def intake(self):
        planner_input, planner_result = self.planner_pair()
        return build_semantic_acceptance_intake(planner_input, planner_result)

    def submission(self, intake=None, verdict="ACCEPT"):
        intake = intake or self.intake()
        packet = intake["packets"][0]
        return {
            "schema": "cml.memory-proposal-queue.semantic-review-submission.v0.4",
            "packet_id": packet["packet_id"],
            "decision_id": packet["decision_id"],
            "pack_id": packet["pack_id"],
            "observed_main_revision": packet["current_main_revision"],
            "reviewer_id": "human:maintainer-1",
            "reviewed_at": "2026-08-15T15:00:00Z",
            "verdict": verdict,
            "rationale": "Reviewed the frozen evidence packet against current main.",
            "reviewed_gate_evidence_refs": list(packet["gate_evidence_refs"]),
            "additional_evidence_refs": ["review-note:manual-001"],
        }

    def test_builds_one_pending_packet_per_review_required_decision(self):
        intake = self.intake()
        self.assertEqual(intake["packet_count"], 1)
        self.assertEqual(intake["pending_human_review_count"], 1)
        self.assertEqual(intake["completed_human_review_count"], 0)
        packet = intake["packets"][0]
        self.assertEqual(packet["status"], "PENDING_HUMAN_SEMANTIC_REVIEW")
        self.assertTrue(packet["human_review_required"])
        self.assertEqual(packet["allowed_human_verdicts"], ["ACCEPT", "REJECT", "DEFER"])
        self.assertFalse(packet["authority_granted"])
        self.assertFalse(packet["acceptance_authority"])

    def test_intake_is_deterministic_for_same_machine_evidence(self):
        planner_input, planner_result = self.planner_pair()
        first = build_semantic_acceptance_intake(planner_input, planner_result)
        second = build_semantic_acceptance_intake(
            copy.deepcopy(planner_input), copy.deepcopy(planner_result)
        )
        self.assertEqual(first, second)
        self.assertTrue(first["intake_digest"].startswith("sha256:"))

    def test_accept_records_support_but_grants_no_acceptance_authority(self):
        intake = self.intake()
        record = validate_human_submission(intake, self.submission(intake, "ACCEPT"))
        self.assertEqual(record["semantic_effect"], "SEMANTIC_SUPPORT_RECORDED")
        self.assertEqual(
            record["next_route"], "SEPARATE_ACCEPTANCE_AUTHORITY_CHECK_REQUIRED"
        )
        self.assertFalse(record["state_mutation_performed"])
        self.assertFalse(record["authority_granted"])
        self.assertFalse(record["acceptance_authority"])
        self.assertFalse(record["merge_authority"])

    def test_reject_records_rejection_but_cannot_close_proposal(self):
        intake = self.intake()
        record = validate_human_submission(intake, self.submission(intake, "REJECT"))
        self.assertEqual(record["semantic_effect"], "SEMANTIC_REJECTION_RECORDED")
        self.assertEqual(
            record["next_route"],
            "SEPARATE_REJECTION_OR_CLOSURE_AUTHORITY_CHECK_REQUIRED",
        )
        self.assertFalse(record["close_authority"])

    def test_defer_records_no_semantic_conclusion(self):
        intake = self.intake()
        record = validate_human_submission(intake, self.submission(intake, "DEFER"))
        self.assertEqual(record["semantic_effect"], "SEMANTIC_REVIEW_DEFERRED")
        self.assertEqual(
            record["next_route"], "AWAIT_NEW_EVIDENCE_OR_FURTHER_HUMAN_REVIEW"
        )

    def test_stale_current_main_binding_fails_closed(self):
        intake = self.intake()
        submission = self.submission(intake)
        submission["observed_main_revision"] = "3" * 40
        with self.assertRaisesRegex(SemanticAcceptanceError, "current main is stale"):
            validate_human_submission(intake, submission)

    def test_reviewed_gate_refs_must_exactly_match_frozen_packet(self):
        intake = self.intake()
        submission = self.submission(intake)
        submission["reviewed_gate_evidence_refs"] = ["different:evidence"]
        with self.assertRaisesRegex(SemanticAcceptanceError, "must exactly match"):
            validate_human_submission(intake, submission)

    def test_decision_and_pack_bindings_fail_closed(self):
        intake = self.intake()
        submission = self.submission(intake)
        submission["decision_id"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(SemanticAcceptanceError, "decision_id does not match"):
            validate_human_submission(intake, submission)

        submission = self.submission(intake)
        submission["pack_id"] = "f" * 64
        with self.assertRaisesRegex(SemanticAcceptanceError, "pack_id does not match"):
            validate_human_submission(intake, submission)

    def test_not_fit_packet_cannot_be_used_as_semantic_acceptance_shortcut(self):
        observation = self.observation()
        observation["observed_source_core_digest"] = SOURCE_CORE_DRIFT
        observation["changed_evidence_components"] = ["source-files"]
        planner_input, planner_result = self.planner_pair(observation)
        intake = build_semantic_acceptance_intake(planner_input, planner_result)
        packet = intake["packets"][0]
        self.assertEqual(packet["status"], "BLOCKED_PENDING_NEW_EVIDENCE_OR_CONTEXT")
        self.assertFalse(packet["human_review_required"])
        submission = self.submission(intake)
        with self.assertRaisesRegex(SemanticAcceptanceError, "not eligible"):
            validate_human_submission(intake, submission)

    def test_authority_escalation_in_planner_result_fails_closed(self):
        planner_input, planner_result = self.planner_pair()
        planner_result["acceptance_authority"] = True
        with self.assertRaisesRegex(SemanticAcceptanceError, "acceptance_authority must be false"):
            build_semantic_acceptance_intake(planner_input, planner_result)


if __name__ == "__main__":
    unittest.main()
