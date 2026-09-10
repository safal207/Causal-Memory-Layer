import unittest

from cml.experimental.focus_field import CandidateScore, RecoveryDecision
from cml.experimental.focus_field_export import (
    FocusFieldExportError,
    SOURCE_CONTRACT,
    export_recovery_decision,
)


class FocusFieldExportTests(unittest.TestCase):
    def decision(self):
        candidate = CandidateScore(
            anchor_id="node-8",
            total=0.81,
            concept_overlap=1.0,
            value_overlap=1.0,
            goal_overlap=1.0,
            causal_overlap=1.0,
            phase_match=1.0,
            temporal_proximity=0.5,
            unresolved_bonus=1.0,
            evidence_quality=1.0,
            verification_ready=True,
            rewind_steps_saved=16,
        )
        return RecoveryDecision(
            state="reanchored",
            selected_anchor_id="node-8",
            score=0.81,
            ranked_candidates=(candidate,),
            rewind_steps_saved=16,
            trusted_continuation=True,
        )

    def test_export_is_portable_and_non_authorizing(self):
        result = export_recovery_decision(
            self.decision(),
            source_revision="2a649903693fc61a560ee056834127ada3120206",
        )

        self.assertEqual(SOURCE_CONTRACT, result["source_contract"])
        self.assertEqual("reanchored", result["state"])
        self.assertEqual("node-8", result["selected_anchor_id"])
        self.assertTrue(result["trusted_continuation"])
        self.assertEqual("ADVISORY_ONLY", result["mode"])
        self.assertFalse(result["authority_granted"])
        self.assertEqual("node-8", result["ranked_candidates"][0]["anchor_id"])
        self.assertTrue(result["ranked_candidates"][0]["verification_ready"])

    def test_export_preserves_exploratory_state_without_promoting_trust(self):
        decision = RecoveryDecision(
            state="reanchored_exploratory",
            selected_anchor_id="old-node",
            score=0.52,
            ranked_candidates=(),
            rewind_steps_saved=9,
            trusted_continuation=False,
        )
        result = export_recovery_decision(
            decision,
            source_revision="2a649903693fc61a560ee056834127ada3120206",
        )

        self.assertEqual("reanchored_exploratory", result["state"])
        self.assertFalse(result["trusted_continuation"])
        self.assertFalse(result["authority_granted"])

    def test_export_rejects_non_full_revision(self):
        with self.assertRaises(FocusFieldExportError):
            export_recovery_decision(self.decision(), source_revision="2a6499")

    def test_export_rejects_non_hex_revision(self):
        with self.assertRaises(FocusFieldExportError):
            export_recovery_decision(self.decision(), source_revision="z" * 40)


if __name__ == "__main__":
    unittest.main()
