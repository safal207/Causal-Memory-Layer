from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from cml.experimental.memory_proposal_queue import (
    QueueAuditError,
    _reject_duplicate_json_object_pairs,
    audit,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "benchmarks" / "experimental" / "memory-proposal-queue-2026-08-15.json"


class MemoryProposalQueueAuditTests(unittest.TestCase):
    def payload(self):
        return json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_current_snapshot_reports_queue_level_pressure_without_authority(self):
        result = audit(self.payload())
        self.assertEqual(result["schema"], "cml.memory-proposal-queue.audit.v0.1")
        self.assertEqual(result["mode"], "REVIEW_ADVISORY_ONLY")
        self.assertFalse(result["authority_granted"])
        self.assertFalse(result["merge_authority"])
        self.assertFalse(result["close_authority"])
        self.assertFalse(result["acceptance_authority"])
        self.assertFalse(result["policy_mutation_authority"])
        self.assertEqual(result["queue"]["proposal_count"], 36)
        self.assertEqual(result["queue"]["pressure"], "CRITICAL_REVIEW_PRESSURE")
        self.assertEqual(result["queue"]["unique_source_pr_count"], 36)
        self.assertEqual(result["queue"]["unique_source_merge_count"], 36)
        self.assertEqual(result["queue"]["unique_pack_id_count"], 36)
        self.assertEqual(
            result["next_safe_transition"],
            "QUEUE_LEVEL_GROUP_REVALIDATE_THEN_REVIEW",
        )

    def test_partial_age_coverage_is_explicit_and_never_filled_in(self):
        result = audit(self.payload())
        self.assertEqual(result["age"]["coverage_count"], 2)
        self.assertEqual(result["age"]["coverage_ratio"], 0.055556)
        self.assertEqual(result["age"]["distribution_status"], "PARTIAL")
        self.assertEqual(result["age"]["oldest_known_created_at"], "2026-07-17T11:20:36+00:00")
        self.assertEqual(result["age"]["newest_known_created_at"], "2026-08-14T05:07:04+00:00")
        self.assertEqual(result["age"]["oldest_known_age_days"], 29.059)
        self.assertEqual(result["age"]["aged_14d_known_count"], 1)

    def test_structural_repetition_is_not_semantic_duplicate_claim(self):
        result = audit(self.payload())
        envelope = result["review_envelope"]
        self.assertEqual(envelope["unique_envelope_count"], 1)
        self.assertEqual(envelope["dominant_envelope_count"], 36)
        self.assertEqual(envelope["dominant_envelope_share"], 1.0)
        self.assertEqual(envelope["structural_repetition_count"], 35)
        self.assertEqual(envelope["semantic_duplicate_status"], "NOT_MEASURED")
        self.assertFalse(envelope["semantic_duplicate_claim"])
        self.assertEqual(result["ancestry"]["status"], "NOT_MEASURED")

    def test_snapshot_must_be_complete_relative_to_reported_total(self):
        payload = self.payload()
        payload["reported_total_count"] = 37
        with self.assertRaisesRegex(QueueAuditError, "snapshot coverage incomplete"):
            audit(payload)

    def test_duplicate_pack_identity_fails_closed(self):
        payload = self.payload()
        payload["proposals"][1]["pack_id"] = payload["proposals"][0]["pack_id"]
        with self.assertRaisesRegex(QueueAuditError, "duplicate pack_id"):
            audit(payload)

    def test_cross_record_pack_swap_changes_snapshot_digest(self):
        payload = self.payload()
        baseline = audit(payload)["snapshot_digest"]
        swapped = copy.deepcopy(payload)
        first = swapped["proposals"][0]["pack_id"]
        swapped["proposals"][0]["pack_id"] = swapped["proposals"][1]["pack_id"]
        swapped["proposals"][1]["pack_id"] = first
        self.assertNotEqual(baseline, audit(swapped)["snapshot_digest"])

    def test_duplicate_json_object_keys_fail_closed(self):
        raw = '{"merge_authority":true,"merge_authority":false}'
        with self.assertRaisesRegex(QueueAuditError, "duplicate JSON key"):
            json.loads(raw, object_pairs_hook=_reject_duplicate_json_object_pairs)

    def test_authority_escalation_fails_closed(self):
        payload = self.payload()
        payload["proposals"][0]["merge_authority"] = True
        with self.assertRaisesRegex(QueueAuditError, "merge_authority must be false"):
            audit(payload)

    def test_future_timestamp_fails_closed(self):
        payload = self.payload()
        payload["proposals"][0]["created_at"] = "2026-08-16T00:00:00Z"
        with self.assertRaisesRegex(QueueAuditError, "cannot be after captured_at"):
            audit(payload)

    def test_digest_is_deterministic(self):
        first = audit(self.payload())["snapshot_digest"]
        second = audit(copy.deepcopy(self.payload()))["snapshot_digest"]
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
