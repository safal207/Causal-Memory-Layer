from __future__ import annotations

import copy
import unittest

from cml.experimental.memory_proposal_queue_revalidation import (
    QueueRevalidationError,
    build_planner_record,
)


PACK = "a" * 64
REPLAY_DRIFT = "b" * 64
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
            "replayed_pack_id": PACK,
            "source_exists": True,
            "source_ancestor_of_main": True,
            "evidence_refs": [
                "https://github.com/safal207/Causal-Memory-Layer/pull/191",
                "https://github.com/safal207/Causal-Memory-Layer/pull/190",
            ],
        }

    def test_clean_source_replay_still_requires_semantic_human_review(self):
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
        self.assertEqual(
            record["revalidation"]["semantic_acceptance_evidence"],
            "NOT_COLLECTED",
        )
        self.assertFalse(record["authority_granted"])
        self.assertFalse(record["acceptance_authority"])
        self.assertFalse(record["merge_authority"])
        self.assertFalse(record["execution_authority"])

    def test_source_replay_drift_blocks_acceptance_pending_new_evidence(self):
        observation = self.observation()
        observation["replayed_pack_id"] = REPLAY_DRIFT
        record = build_planner_record(observation)
        self.assertEqual(record["applicability"]["status"], "DRIFT")
        self.assertIn("source_digest_mismatch", record["applicability"]["reasons"])
        self.assertEqual(record["quality"]["readiness"], "REVIEW")
        self.assertEqual(record["claimed_fitness_status"], "NOT_FIT")

    def test_non_ancestor_source_is_revalidation_evidence_not_delete_authority(self):
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

    def test_even_current_commit_match_cannot_skip_semantic_acceptance_review(self):
        observation = self.observation()
        observation["current_main_revision"] = SOURCE
        record = build_planner_record(observation)
        self.assertEqual(record["applicability"]["status"], "MATCH")
        self.assertEqual(record["quality"]["readiness"], "REVIEW")
        self.assertEqual(record["claimed_fitness_status"], "REVIEW_REQUIRED")

    def test_proposal_pack_identity_mismatch_fails_closed(self):
        observation = self.observation()
        observation["validated_pack_id"] = REPLAY_DRIFT
        with self.assertRaisesRegex(
            QueueRevalidationError,
            "identity contradicts proposal pack_id",
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
