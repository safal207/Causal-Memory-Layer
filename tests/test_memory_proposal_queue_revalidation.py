from __future__ import annotations

import copy
import unittest

from cml.experimental.memory_proposal_queue_revalidation import (
    QueueRevalidationError,
    build_planner_record,
)


PACK = "a" * 64
REPLAY = "b" * 64
SOURCE_CORE = "c" * 64
SOURCE_CORE_DRIFT = "d" * 64
SOURCE = "1" * 40
MAIN = "2" * 40


class MemoryProposalQueueRevalidationTests(unittest.TestCase):
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

    def test_mutable_pr_and_check_drift_do_not_become_source_identity_drift(self):
        record = build_planner_record(self.observation())
        self.assertEqual(record["applicability"]["status"], "REVALIDATE")
        self.assertIn(
            "environment_mismatch:commit_sha",
            record["applicability"]["reasons"],
        )
        self.assertEqual(record["quality"]["semantic_truth"], "SUPPORTED")
        self.assertEqual(record["quality"]["completeness"], "INCOMPLETE")
        self.assertEqual(record["quality"]["readiness"], "REVIEW")
        self.assertIn(
            "completeness_missing:semantic_acceptance",
            record["quality"]["reasons"],
        )
        self.assertEqual(record["claimed_fitness_status"], "REVIEW_REQUIRED")
        self.assertFalse(record["revalidation"]["full_pack_replay_match"])
        self.assertTrue(record["revalidation"]["stable_source_core_match"])
        self.assertEqual(
            record["revalidation"]["descriptive_metadata_changed_components"],
            ["source-pr"],
        )
        self.assertEqual(
            record["revalidation"]["operational_evidence_changed_components"],
            ["source-checks"],
        )
        self.assertEqual(
            record["revalidation"]["mutable_evidence_changed_components"],
            ["source-pr", "source-checks"],
        )
        self.assertEqual(
            record["revalidation"]["immutable_evidence_changed_components"],
            [],
        )
        self.assertFalse(record["authority_granted"])
        self.assertFalse(record["acceptance_authority"])

    def test_stable_source_core_drift_is_canonical_drift_and_not_fit(self):
        observation = self.observation()
        observation["observed_source_core_digest"] = SOURCE_CORE_DRIFT
        observation["changed_evidence_components"] = ["source-files", "source-checks"]
        record = build_planner_record(observation)
        self.assertEqual(record["applicability"]["status"], "DRIFT")
        self.assertIn("source_digest_mismatch", record["applicability"]["reasons"])
        self.assertEqual(record["claimed_fitness_status"], "NOT_FIT")
        self.assertFalse(record["revalidation"]["stable_source_core_match"])

    def test_non_ancestor_source_requires_revalidation_not_delete_authority(self):
        observation = self.observation()
        observation["source_ancestor_of_main"] = False
        record = build_planner_record(observation)
        self.assertEqual(record["applicability"]["status"], "REVALIDATE")
        self.assertTrue(
            any(
                reason.startswith("lineage_invalidated:source-merge:")
                for reason in record["applicability"]["reasons"]
            )
        )
        self.assertEqual(record["claimed_fitness_status"], "REVIEW_REQUIRED")
        self.assertFalse(record["close_authority"])
        self.assertFalse(record["policy_mutation_authority"])

    def test_even_exact_current_source_cannot_skip_semantic_acceptance_review(self):
        observation = self.observation()
        observation["current_main_revision"] = SOURCE
        observation["replayed_pack_id"] = PACK
        observation["full_pack_replay_match"] = True
        observation["changed_evidence_components"] = []
        record = build_planner_record(observation)
        self.assertEqual(record["applicability"]["status"], "MATCH")
        self.assertEqual(record["quality"]["readiness"], "REVIEW")
        self.assertEqual(record["claimed_fitness_status"], "REVIEW_REQUIRED")

    def test_proposal_pack_identity_mismatch_fails_closed(self):
        observation = self.observation()
        observation["validated_pack_id"] = REPLAY
        with self.assertRaisesRegex(
            QueueRevalidationError,
            "identity contradicts proposal pack_id",
        ):
            build_planner_record(observation)

    def test_immutable_evidence_change_cannot_claim_stable_core_match(self):
        observation = self.observation()
        observation["changed_evidence_components"] = ["source-files"]
        with self.assertRaisesRegex(
            QueueRevalidationError,
            "stable source core cannot match",
        ):
            build_planner_record(observation)

    def test_result_is_deterministic_for_same_observation(self):
        first = build_planner_record(self.observation())
        second = build_planner_record(copy.deepcopy(self.observation()))
        self.assertEqual(first, second)
        self.assertTrue(
            first["revalidation"]["observation_digest"].startswith("sha256:")
        )


if __name__ == "__main__":
    unittest.main()
