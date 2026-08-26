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
from cml.experimental.memory_proposal_semantic_acceptance import (
    INTAKE_SCHEMA,
    _digest as semantic_digest,
    _packet_identity as semantic_packet_identity,
)


MAIN = "1" * 40
SOURCE_PLAN_DIGEST = "sha256:" + "9" * 64
SOURCE_AUDIT_DIGEST = "sha256:" + "8" * 64
CAPTURED_AT = "2026-08-15T14:22:27+00:00"


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
        packet = {
            "status": "PENDING_HUMAN_SEMANTIC_REVIEW",
            "human_review_required": True,
            "decision_id": f"sha256:{proposal_pr + 100:064x}",
            "proposal_pr": proposal_pr,
            "source_pr": proposal_pr - 1,
            "source_merge": f"{proposal_pr + 300:040x}",
            "pack_id": f"{proposal_pr + 200:064x}",
            "current_main_revision": MAIN,
            "observation_digest": f"sha256:{proposal_pr + 400:064x}",
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
        packet["packet_id"] = semantic_digest(semantic_packet_identity(packet))
        return packet

    def blocked_packet(self, proposal_pr: int):
        packet = self.packet(proposal_pr)
        packet["status"] = "BLOCKED_PENDING_NEW_EVIDENCE_OR_CONTEXT"
        packet["human_review_required"] = False
        packet["machine_gate"]["canonical_fitness_status"] = "NOT_FIT"
        packet["machine_gate"]["review_route"] = (
            "BLOCK_ACCEPTANCE_PENDING_NEW_EVIDENCE_OR_CONTEXT"
        )
        packet["packet_id"] = semantic_digest(semantic_packet_identity(packet))
        return packet

    def intake(self, packets):
        packet_ids = sorted(packet["packet_id"] for packet in packets)
        pending_count = sum(packet.get("human_review_required") is True for packet in packets)
        blocked_count = sum(
            packet.get("status") == "BLOCKED_PENDING_NEW_EVIDENCE_OR_CONTEXT"
            for packet in packets
        )
        authority_only_count = sum(
            packet.get("status") == "SEPARATE_AUTHORITY_REVIEW_ONLY"
            for packet in packets
        )
        intake = {
            "schema": INTAKE_SCHEMA,
            "mode": "HUMAN_SEMANTIC_REVIEW_INTAKE_ONLY",
            "source_plan_digest": SOURCE_PLAN_DIGEST,
            "source_audit_digest": SOURCE_AUDIT_DIGEST,
            "current_main_revision": MAIN,
            "captured_at": CAPTURED_AT,
            "packet_count": len(packets),
            "pending_human_review_count": pending_count,
            "blocked_pending_evidence_count": blocked_count,
            "separate_authority_review_only_count": authority_only_count,
            "completed_human_review_count": 0,
            "packets": packets,
            **authority_false(),
        }
        intake["intake_digest"] = semantic_digest(
            {
                "source_plan_digest": SOURCE_PLAN_DIGEST,
                "source_audit_digest": SOURCE_AUDIT_DIGEST,
                "current_main_revision": MAIN,
                "captured_at": CAPTURED_AT,
                "packet_ids": packet_ids,
            }
        )
        return intake

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

    def contexts(self, contexts, intake):
        return {
            "schema": CONTEXT_SCHEMA,
            "source_intake_digest": intake["intake_digest"],
            "current_main_revision": MAIN,
            "context_count": len(contexts),
            "contexts": contexts,
        }

    def build(self, packets, contexts):
        intake = self.intake(packets)
        return build_review_workbench(intake, self.contexts(contexts, intake))

    def test_preserves_one_card_per_packet_and_no_authority(self):
        packets = [self.packet(191), self.packet(194)]
        result = self.build(packets, [self.context(item) for item in packets])
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
        result = self.build(
            [diverged_packet, missing_packet],
            [
                self.context(diverged_packet, path_status=PATH_DIVERGED),
                self.context(missing_packet, path_status=PATH_MISSING),
            ],
        )
        self.assertEqual(result["cards"][0]["proposal_pr"], 191)
        self.assertEqual(result["cards"][0]["priority_class"], "P0_SOURCE_SCOPE_MISSING")
        self.assertEqual(result["cards"][1]["priority_class"], "P1_SOURCE_SCOPE_DIVERGED")

    def test_review_context_drift_precedes_operational_refresh(self):
        review_packet = self.packet(191, ["source-reviews", "source-checks"])
        checks_packet = self.packet(194, ["source-checks"])
        result = self.build(
            [checks_packet, review_packet],
            [self.context(checks_packet), self.context(review_packet)],
        )
        self.assertEqual(result["cards"][0]["proposal_pr"], 191)
        self.assertEqual(result["cards"][0]["priority_class"], "P2_REVIEW_CONTEXT_DRIFT")
        self.assertEqual(result["cards"][1]["priority_class"], "P3_OPERATIONAL_EVIDENCE_REFRESH")

    def test_lower_lesson_confidence_breaks_ties_first(self):
        low = self.packet(191)
        high = self.packet(194)
        result = self.build(
            [high, low],
            [self.context(high, confidence=90), self.context(low, confidence=60)],
        )
        self.assertEqual(result["cards"][0]["proposal_pr"], 191)

    def test_broader_scope_breaks_remaining_ties_first(self):
        narrow = self.packet(191)
        broad = self.packet(194)
        result = self.build(
            [narrow, broad],
            [
                self.context(narrow, confidence=75),
                self.context(broad, confidence=75, extra_path=True),
            ],
        )
        self.assertEqual(result["cards"][0]["proposal_pr"], 194)

    def test_input_order_does_not_change_workbench(self):
        first = self.packet(191)
        second = self.packet(194)
        intake_a = self.intake([first, second])
        contexts_a = self.contexts([self.context(first), self.context(second)], intake_a)
        intake_b = self.intake([second, first])
        contexts_b = self.contexts([self.context(second), self.context(first)], intake_b)
        self.assertEqual(
            build_review_workbench(intake_a, contexts_a),
            build_review_workbench(intake_b, contexts_b),
        )

    def test_submission_template_is_bound_but_has_no_fabricated_human_verdict(self):
        packet = self.packet(191)
        result = self.build([packet], [self.context(packet)])
        card = result["cards"][0]
        self.assertTrue(card["human_review_required"])
        template = card["submission_template"]
        self.assertEqual(template["packet_id"], packet["packet_id"])
        self.assertEqual(template["decision_id"], packet["decision_id"])
        self.assertEqual(template["observed_main_revision"], MAIN)
        self.assertIsNone(template["reviewer_id"])
        self.assertIsNone(template["reviewed_at"])
        self.assertIsNone(template["verdict"])
        self.assertIsNone(template["rationale"])

    def test_blocked_packet_has_no_submission_template_or_pending_review(self):
        packet = self.blocked_packet(191)
        result = self.build([packet], [self.context(packet)])
        card = result["cards"][0]
        self.assertEqual(result["card_count"], 1)
        self.assertEqual(result["pending_review_count"], 0)
        self.assertFalse(card["human_review_required"])
        self.assertIsNone(card["submission_template"])
        rendered = render_markdown(result)
        self.assertIn("Human semantic review required:** no", rendered)
        self.assertIn("no semantic-review submission is permitted", rendered)

    def test_stale_context_main_fails_closed(self):
        packet = self.packet(191)
        intake = self.intake([packet])
        payload = self.contexts([self.context(packet)], intake)
        payload["current_main_revision"] = "2" * 40
        with self.assertRaisesRegex(ReviewWorkbenchError, "stale"):
            build_review_workbench(intake, payload)

    def test_context_source_pr_mismatch_fails_closed(self):
        packet = self.packet(191)
        intake = self.intake([packet])
        context = self.context(packet)
        context["source_pr"] = packet["source_pr"] + 100
        with self.assertRaisesRegex(ReviewWorkbenchError, "context source PR mismatch"):
            build_review_workbench(intake, self.contexts([context], intake))

    def test_context_pack_mismatch_fails_closed(self):
        packet = self.packet(191)
        intake = self.intake([packet])
        context = self.context(packet)
        context["pack_id"] = "f" * 64
        with self.assertRaisesRegex(ReviewWorkbenchError, "context pack mismatch"):
            build_review_workbench(intake, self.contexts([context], intake))

    def test_same_path_cannot_hide_blob_divergence(self):
        packet = self.packet(191)
        intake = self.intake([packet])
        context = self.context(packet)
        context["path_states"][0]["current_blob_sha"] = "e" * 40
        with self.assertRaisesRegex(ReviewWorkbenchError, "SAME path"):
            build_review_workbench(intake, self.contexts([context], intake))

    def test_workbench_digest_binds_rendered_context_and_evidence(self):
        packet = self.packet(191)
        baseline_context = self.context(packet)
        changed_context = copy.deepcopy(baseline_context)
        changed_context["source_title"] = "Different source title"
        changed_context["context_evidence_refs"] = ["https://example.test/context/rebound"]
        baseline = self.build([packet], [baseline_context])
        changed = self.build([packet], [changed_context])
        self.assertNotEqual(baseline["workbench_digest"], changed["workbench_digest"])

    def test_tampered_intake_is_rejected_before_workbench_build(self):
        packet = self.packet(191)
        intake = self.intake([packet])
        contexts = self.contexts([self.context(packet)], intake)
        intake["packets"][0]["machine_gate"]["review_route"] = "FORGED_ROUTE"
        with self.assertRaisesRegex(ReviewWorkbenchError, "frozen semantic intake is invalid"):
            build_review_workbench(intake, contexts)

    def test_markdown_is_review_guidance_not_a_verdict(self):
        packet = self.packet(191)
        result = self.build([packet], [self.context(packet)])
        rendered = render_markdown(result)
        self.assertIn("Queue rank orders review attention only", rendered)
        self.assertIn("Reuse only when recorded constraints still apply", rendered)
        self.assertNotIn("verdict=ACCEPT", rendered)
        self.assertNotIn("accepted Memory Pack", rendered)

    def test_markdown_escapes_forged_card_content(self):
        packet = self.packet(191)
        context = self.context(packet)
        context["source_title"] = "Fix parser\n\n## forged\n**Verdict:** ACCEPT"
        result = self.build([packet], [context])
        rendered = render_markdown(result)
        headings = [line for line in rendered.splitlines() if line.startswith("## ")]
        self.assertEqual(len(headings), 1)
        self.assertNotIn("\n## forged", rendered)


if __name__ == "__main__":
    unittest.main()
