from __future__ import annotations

import copy
import unittest

from cml.experimental.memory_proposal_review_workbench import (
    CONTEXT_SCHEMA,
    PATH_DIVERGED,
    PATH_MISSING,
    PATH_SAME,
    ReviewWorkbenchError,
    build_review_workbench,
    render_markdown,
)
from cml.experimental.memory_proposal_semantic_acceptance import INTAKE_SCHEMA


MAIN = "1" * 40
INTAKE_DIGEST = "sha256:" + "a" * 64


def authority_false():
    return {
        "authority_granted": False,
        "merge_authority": False,
        "close_authority": False,
        "acceptance_authority": False,
        "execution_authority": False,
        "policy_mutation_authority": False,
    }


class MemoryProposalReviewWorkbenchTests(unittest.TestCase):
    def packet(self, proposal_pr: int, changed=None):
        changed = ["source-checks"] if changed is None else changed
        return {
            "packet_id": f"sha256:{proposal_pr:064x}",
            "decision_id": f"sha256:{proposal_pr + 100:064x}",
            "proposal_pr": proposal_pr,
            "source_pr": proposal_pr - 1,
            "pack_id": f"{proposal_pr + 200:064x}",
            "current_main_revision": MAIN,
            "machine_gate": {
                "applicability_status": "REVALIDATE",
                "quality_readiness": "REVIEW",
                "canonical_fitness_status": "REVIEW_REQUIRED",
                "review_route": "HUMAN_REVALIDATION_REQUIRED",
                "stable_source_core_match": True,
                "source_ancestor_of_main": True,
                "changed_evidence_components": changed,
            },
            "gate_evidence_refs": [f"https://example.test/gate/{proposal_pr}"],
            "lineage_evidence_refs": [f"https://example.test/lineage/{proposal_pr}"],
            "allowed_human_verdicts": ["ACCEPT", "REJECT", "DEFER"],
            **authority_false(),
        }

    def intake(self, packets):
        return {
            "schema": INTAKE_SCHEMA,
            "intake_digest": INTAKE_DIGEST,
            "current_main_revision": MAIN,
            "packets": packets,
            **authority_false(),
        }

    def context(
        self,
        packet,
        *,
        path_status=PATH_SAME,
        confidence=75,
        created_at="2026-07-17T11:20:21Z",
        extra_path=False,
    ):
        source_blob = "b" * 40
        if path_status == PATH_SAME:
            current_blob = source_blob
        elif path_status == PATH_DIVERGED:
            current_blob = "c" * 40
        else:
            current_blob = None
        states = [
            {
                "path": f"docs/pr-{packet['source_pr']}.md",
                "status": path_status,
                "source_blob_sha": source_blob,
                "current_blob_sha": current_blob,
            }
        ]
        if extra_path:
            states.append(
                {
                    "path": f"src/pr-{packet['source_pr']}.py",
                    "status": PATH_SAME,
                    "source_blob_sha": "d" * 40,
                    "current_blob_sha": "d" * 40,
                }
            )
        return {
            "packet_id": packet["packet_id"],
            "decision_id": packet["decision_id"],
            "proposal_pr": packet["proposal_pr"],
            "source_pr": packet["source_pr"],
            "pack_id": packet["pack_id"],
            "current_main_revision": MAIN,
            "source_title": f"Source PR {packet['source_pr']}",
            "situation_label": "Observed repository situation",
            "action_label": "Apply the merged approach",
            "lesson_label": "Reuse only when recorded constraints still apply",
            "lesson_confidence": confidence,
            "pack_created_at": created_at,
            "path_states": states,
            "context_evidence_refs": [f"https://example.test/context/{packet['proposal_pr']}"],
        }

    def contexts(self, contexts):
        return {
            "schema": CONTEXT_SCHEMA,
            "source_intake_digest": INTAKE_DIGEST,
            "current_main_revision": MAIN,
            "contexts": contexts,
        }

    def test_preserves_one_card_per_packet_and_no_authority(self):
        packets = [self.packet(191), self.packet(194)]
        result = build_review_workbench(
            self.intake(packets),
            self.contexts([self.context(item) for item in packets]),
        )
        self.assertEqual(result["card_count"], 2)
        self.assertEqual(result["pending_review_count"], 2)
        self.assertEqual(result["completed_review_count"], 0)
        self.assertEqual(len({card["packet_id"] for card in result["cards"]}), 2)
        self.assertFalse(result["authority_granted"])
        for card in result["cards"]:
            self.assertFalse(card["acceptance_authority"])
            self.assertFalse(card["merge_authority"])
            self.assertFalse(card["review_completed"])

    def test_missing_scope_is_reviewed_before_diverged_scope(self):
        missing_packet = self.packet(191)
        diverged_packet = self.packet(194)
        result = build_review_workbench(
            self.intake([diverged_packet, missing_packet]),
            self.contexts(
                [
                    self.context(diverged_packet, path_status=PATH_DIVERGED),
                    self.context(missing_packet, path_status=PATH_MISSING),
                ]
            ),
        )
        self.assertEqual(result["cards"][0]["proposal_pr"], 191)
        self.assertEqual(result["cards"][0]["priority_class"], "P0_SOURCE_SCOPE_MISSING")
        self.assertEqual(result["cards"][1]["priority_class"], "P1_SOURCE_SCOPE_DIVERGED")

    def test_review_context_drift_precedes_operational_refresh(self):
        review_packet = self.packet(191, ["source-reviews", "source-checks"])
        checks_packet = self.packet(194, ["source-checks"])
        result = build_review_workbench(
            self.intake([checks_packet, review_packet]),
            self.contexts([self.context(checks_packet), self.context(review_packet)]),
        )
        self.assertEqual(result["cards"][0]["proposal_pr"], 191)
        self.assertEqual(result["cards"][0]["priority_class"], "P2_REVIEW_CONTEXT_DRIFT")
        self.assertEqual(result["cards"][1]["priority_class"], "P3_OPERATIONAL_EVIDENCE_REFRESH")

    def test_lower_lesson_confidence_breaks_ties_first(self):
        low = self.packet(191)
        high = self.packet(194)
        result = build_review_workbench(
            self.intake([high, low]),
            self.contexts(
                [self.context(high, confidence=90), self.context(low, confidence=60)]
            ),
        )
        self.assertEqual(result["cards"][0]["proposal_pr"], 191)

    def test_broader_scope_breaks_remaining_ties_first(self):
        narrow = self.packet(191)
        broad = self.packet(194)
        result = build_review_workbench(
            self.intake([narrow, broad]),
            self.contexts(
                [
                    self.context(narrow, confidence=75),
                    self.context(broad, confidence=75, extra_path=True),
                ]
            ),
        )
        self.assertEqual(result["cards"][0]["proposal_pr"], 194)

    def test_input_order_does_not_change_workbench(self):
        first = self.packet(191)
        second = self.packet(194)
        intake_a = self.intake([first, second])
        contexts_a = self.contexts([self.context(first), self.context(second)])
        intake_b = self.intake([second, first])
        contexts_b = self.contexts([self.context(second), self.context(first)])
        self.assertEqual(
            build_review_workbench(intake_a, contexts_a),
            build_review_workbench(intake_b, contexts_b),
        )

    def test_submission_template_is_bound_but_has_no_fabricated_human_verdict(self):
        packet = self.packet(191)
        result = build_review_workbench(
            self.intake([packet]), self.contexts([self.context(packet)])
        )
        template = result["cards"][0]["submission_template"]
        self.assertEqual(template["packet_id"], packet["packet_id"])
        self.assertEqual(template["decision_id"], packet["decision_id"])
        self.assertEqual(template["observed_main_revision"], MAIN)
        self.assertIsNone(template["reviewer_id"])
        self.assertIsNone(template["reviewed_at"])
        self.assertIsNone(template["verdict"])
        self.assertIsNone(template["rationale"])

    def test_stale_context_main_fails_closed(self):
        packet = self.packet(191)
        payload = self.contexts([self.context(packet)])
        payload["current_main_revision"] = "2" * 40
        with self.assertRaisesRegex(ReviewWorkbenchError, "stale"):
            build_review_workbench(self.intake([packet]), payload)

    def test_context_pack_mismatch_fails_closed(self):
        packet = self.packet(191)
        context = self.context(packet)
        context["pack_id"] = "f" * 64
        with self.assertRaisesRegex(ReviewWorkbenchError, "context pack mismatch"):
            build_review_workbench(self.intake([packet]), self.contexts([context]))

    def test_same_path_cannot_hide_blob_divergence(self):
        packet = self.packet(191)
        context = self.context(packet)
        context["path_states"][0]["current_blob_sha"] = "e" * 40
        with self.assertRaisesRegex(ReviewWorkbenchError, "SAME path"):
            build_review_workbench(self.intake([packet]), self.contexts([context]))

    def test_markdown_is_review_guidance_not_a_verdict(self):
        packet = self.packet(191)
        result = build_review_workbench(
            self.intake([packet]), self.contexts([self.context(packet)])
        )
        rendered = render_markdown(result)
        self.assertIn("Queue rank orders review attention only", rendered)
        self.assertIn("Reuse only when recorded constraints still apply", rendered)
        self.assertNotIn("verdict=ACCEPT", rendered)
        self.assertNotIn("accepted Memory Pack", rendered)


if __name__ == "__main__":
    unittest.main()
