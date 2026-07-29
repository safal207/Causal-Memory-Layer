from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "validate_caep", HERE / "validate_caep.py"
)
assert SPEC and SPEC.loader
validate_caep = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validate_caep)


class CAEPValidationTests(unittest.TestCase):
    """Regression coverage for CAEP schema, semantics, and causal bindings."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = validate_caep.load_json(HERE / "caep.schema.json")
        cls.success = validate_caep.load_json(HERE / "caep.example.json")
        cls.diverged = validate_caep.load_json(
            HERE / "caep.diverged.example.json"
        )
        cls.recovered = validate_caep.load_json(
            HERE / "caep.recovered.example.json"
        )

    def _redigest(self, record: dict) -> None:
        record["integrity"]["record_digest"]["value"] = (
            validate_caep.compute_record_digest(record)
        )

    def test_valid_examples(self) -> None:
        self.assertEqual(
            validate_caep.validate_record(self.schema, self.success), []
        )
        self.assertEqual(
            validate_caep.validate_record(self.schema, self.diverged), []
        )
        self.assertEqual(
            validate_caep.validate_record(
                self.schema, self.recovered, [self.diverged]
            ),
            [],
        )

    def test_schema_invalid_input_does_not_run_semantics(self) -> None:
        errors = validate_caep.validate_record(self.schema, [])
        self.assertTrue(errors)
        self.assertTrue(all(error.startswith("schema:") for error in errors))

    def test_accepted_status_requires_independent_verification(self) -> None:
        record = copy.deepcopy(self.success)
        record["verification"]["independence"] = "same_actor"
        self._redigest(record)
        schema_messages = validate_caep.schema_errors(self.schema, record)
        semantic_messages = validate_caep.semantic_errors(record)
        self.assertTrue(schema_messages)
        self.assertTrue(
            any(
                "independent verification" in error
                for error in semantic_messages
            )
        )

    def test_independent_verification_requires_verifier(self) -> None:
        record = copy.deepcopy(self.success)
        record["verification"].pop("verifier")
        errors = validate_caep.validate_record(self.schema, record)
        self.assertTrue(any("verifier" in error for error in errors))

    def test_independent_verifier_differs_from_decision_maker(self) -> None:
        record = copy.deepcopy(self.success)
        record["verification"]["verifier"]["ref"] = (
            record["decision"]["maker"]["ref"]
        )
        self._redigest(record)
        errors = validate_caep.validate_record(self.schema, record)
        self.assertTrue(any("decision maker" in error for error in errors))

    def test_unknown_and_uncovered_postcondition_fail(self) -> None:
        record = copy.deepcopy(self.success)
        record["verification"]["checks"][0]["postcondition_id"] = "unknown"
        self._redigest(record)
        errors = validate_caep.validate_record(self.schema, record)
        self.assertTrue(
            any("undeclared postconditions" in error for error in errors)
        )
        self.assertTrue(
            any("lack verification checks" in error for error in errors)
        )

    def test_accepted_write_requires_critical_postcondition(self) -> None:
        record = copy.deepcopy(self.success)
        record["expected_postconditions"][0]["severity"] = "info"
        self._redigest(record)
        schema_messages = validate_caep.schema_errors(self.schema, record)
        semantic_messages = validate_caep.semantic_errors(record)
        self.assertTrue(schema_messages)
        self.assertTrue(any("critical" in error for error in semantic_messages))

    def test_recovered_status_must_be_consistent(self) -> None:
        record = copy.deepcopy(self.recovered)
        record["recovery"]["status"] = "failed"
        self._redigest(record)
        errors = validate_caep.validate_record(
            self.schema, record, [self.diverged]
        )
        self.assertTrue(errors)
        self.assertTrue(
            any("recovered" in error or "failed" in error for error in errors)
        )

    def test_record_tampering_breaks_digest(self) -> None:
        record = copy.deepcopy(self.success)
        record["decision"]["summary"] = "tampered"
        errors = validate_caep.validate_record(self.schema, record)
        self.assertTrue(
            any("record digest mismatch" in error for error in errors)
        )

    def test_parent_tampering_breaks_binding(self) -> None:
        parent = copy.deepcopy(self.diverged)
        parent["decision"]["summary"] = "tampered parent"
        errors = validate_caep.validate_record(
            self.schema, self.recovered, [parent]
        )
        self.assertTrue(
            any(
                "invalid record digest" in error
                or "parent binding mismatch" in error
                for error in errors
            )
        )

    def test_non_root_record_requires_supplied_parent(self) -> None:
        errors = validate_caep.validate_record(self.schema, self.recovered)
        self.assertTrue(
            any(
                "missing supplied parent record: caep_diverged_01" in error
                for error in errors
            )
        )

    def test_cli_recovered_without_parent_is_invalid(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(HERE / "validate_caep.py"),
                str(HERE / "caep.recovered.example.json"),
            ],
            cwd=HERE,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("INVALID", result.stdout)
        self.assertIn("missing supplied parent record", result.stdout)

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "duplicate.json"
            path.write_text(
                '{"episode_id":"a","episode_id":"b"}',
                encoding="utf-8",
            )
            with self.assertRaises(validate_caep.DuplicateKeyError):
                validate_caep.load_json(path)

    def test_temporal_order_is_enforced(self) -> None:
        record = copy.deepcopy(self.success)
        record["verification"]["verified_at"] = "2026-07-29T17:00:01Z"
        self._redigest(record)
        errors = validate_caep.validate_record(self.schema, record)
        self.assertTrue(
            any("outcome.observed_at" in error for error in errors)
        )

    def test_temporal_dispatch_event_is_explicit(self) -> None:
        trajectory = json.loads(
            (HERE / "caep.absurdity-trajectory.json").read_text(
                encoding="utf-8"
            )
        )
        events = {event["id"]: event for event in trajectory["events"]}
        self.assertEqual(events["N4"]["type"], "tool_dispatch")
        self.assertLess(
            events["N3"]["valid_time"], events["N4"]["valid_time"]
        )
        self.assertGreater(
            events["N3"]["recorded_time"],
            events["N4"]["recorded_time"],
        )


if __name__ == "__main__":
    unittest.main()
