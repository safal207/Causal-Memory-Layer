from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from cml.experimental.memory_proposal_queue_planner import QueuePlanningError, plan


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (
    ROOT
    / "benchmarks"
    / "experimental"
    / "memory-proposal-queue-planner-v0.2.synthetic.json"
)


class MemoryProposalQueuePlannerTests(unittest.TestCase):
    def payload(self):
        return json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_one_decision_is_preserved_per_pack_without_authority(self):
        result = plan(self.payload())
        self.assertEqual(
            result["schema"],
            "cml.memory-proposal-queue.revalidation-plan.v0.2",
        )
        self.assertEqual(result["mode"], "REVIEW_ADVISORY_ONLY")
        self.assertTrue(result["synthetic"])
        self.assertFalse(result["authority_granted"])
        self.assertFalse(result["merge_authority"])
        self.assertFalse(result["close_authority"])
        self.assertFalse(result["acceptance_authority"])
        self.assertFalse(result["execution_authority"])
        self.assertFalse(result["policy_mutation_authority"])
        self.assertEqual(result["record_count"], 6)
        self.assertEqual(len(result["decisions"]), 6)
        self.assertEqual(len({item["decision_id"] for item in result["decisions"]}), 6)
        self.assertEqual(len({item["pack_id"] for item in result["decisions"]}), 6)
        self.assertTrue(all(not item["acceptance_authority"] for item in result["decisions"]))

    def test_grouping_is_lineage_and_fitness_scoped_not_semantic_merge(self):
        result = plan(self.payload())
        self.assertEqual(result["group_count"], 5)

        groups = {
            (item["lineage_root_id"], item["canonical_fitness_status"]): item
            for item in result["groups"]
        }
        ready = groups[("pr-contracts", "READY_FOR_AUTHORITY_CHECK")]
        self.assertEqual(ready["group_size"], 2)
        self.assertEqual(ready["proposal_prs"], [1001, 1002])
        self.assertEqual(ready["scope"], "REVIEW_ERGONOMICS_ONLY")
        self.assertFalse(ready["semantic_merge"])
        self.assertFalse(ready["group_decision_authority"])

        review = groups[("pr-contracts", "REVIEW_REQUIRED")]
        self.assertEqual(review["group_size"], 1)
        self.assertEqual(review["proposal_prs"], [1003])

    def test_canonical_cml_fitness_drives_review_route(self):
        result = plan(self.payload())
        routes = {item["proposal_pr"]: item["review_route"] for item in result["decisions"]}
        self.assertEqual(routes[1001], "ELIGIBLE_FOR_SEPARATE_ACCEPTANCE_REVIEW")
        self.assertEqual(routes[1003], "HUMAN_REVALIDATION_REQUIRED")
        self.assertEqual(routes[1004], "HUMAN_REVALIDATION_REQUIRED")
        self.assertEqual(
            routes[1005],
            "BLOCK_ACCEPTANCE_PENDING_NEW_EVIDENCE_OR_CONTEXT",
        )
        self.assertEqual(
            routes[1006],
            "BLOCK_ACCEPTANCE_PENDING_NEW_EVIDENCE_OR_CONTEXT",
        )
        self.assertTrue(
            all(
                not item["canonical_fitness"]["authorizes_action"]
                for item in result["decisions"]
            )
        )

    def test_claimed_fitness_must_match_canonical_composition(self):
        payload = self.payload()
        payload["records"][2]["claimed_fitness_status"] = "READY_FOR_AUTHORITY_CHECK"
        with self.assertRaisesRegex(
            QueuePlanningError,
            "contradicts canonical CML fitness",
        ):
            plan(payload)

    def test_revalidation_coverage_must_be_complete(self):
        payload = self.payload()
        payload["expected_record_count"] = 7
        with self.assertRaisesRegex(QueuePlanningError, "revalidation coverage incomplete"):
            plan(payload)

    def test_duplicate_pack_identity_fails_closed(self):
        payload = self.payload()
        payload["records"][1]["pack_id"] = payload["records"][0]["pack_id"]
        with self.assertRaisesRegex(QueuePlanningError, "duplicate pack_id"):
            plan(payload)

    def test_lineage_group_requires_explicit_evidence(self):
        payload = self.payload()
        payload["records"][0]["lineage_evidence_refs"] = []
        with self.assertRaisesRegex(QueuePlanningError, "lineage_evidence_refs must not be empty"):
            plan(payload)

    def test_plan_digest_is_deterministic(self):
        first = plan(self.payload())["plan_digest"]
        second = plan(copy.deepcopy(self.payload()))["plan_digest"]
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("sha256:"))

    def test_plan_digest_binds_synthetic_mode(self):
        payload = self.payload()
        baseline = plan(payload)["plan_digest"]
        changed = copy.deepcopy(payload)
        changed["synthetic"] = not changed["synthetic"]
        self.assertNotEqual(baseline, plan(changed)["plan_digest"])

    def test_plan_digest_binds_current_main_revision(self):
        payload = self.payload()
        baseline = plan(payload)["plan_digest"]
        changed = copy.deepcopy(payload)
        changed["current_main_revision"] = "f" * 40
        self.assertNotEqual(baseline, plan(changed)["plan_digest"])


if __name__ == "__main__":
    unittest.main()
