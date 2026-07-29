from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


class InteroperabilityDemoTests(unittest.TestCase):
    """Exercise happy and recovery paths across process boundaries."""

    def test_happy_and_recovery_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "bundle.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(HERE / "run_demo.py"),
                    "--output",
                    str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            summary = json.loads(result.stdout)
            self.assertEqual(summary["caep_validation"], "valid")
            self.assertEqual(summary["happy"], "verified")
            self.assertEqual(summary["diverged"], "diverged")
            self.assertEqual(summary["recovered"], "verified")

            bundle = json.loads(output.read_text(encoding="utf-8"))
            recovered = bundle["recovery_path"]["recovered_record"]
            diverged = bundle["recovery_path"]["diverged_record"]
            self.assertEqual(
                recovered["causal_parent_ids"],
                [diverged["episode_id"]],
            )
            self.assertEqual(
                recovered["integrity"]["parent_digests"]
                [diverged["episode_id"]]["value"],
                diverged["integrity"]["record_digest"]["value"],
            )
            self.assertEqual(
                recovered["verification"]["independence"],
                "independent",
            )
            self.assertEqual(
                recovered["verification"]["checks"][0]["result"],
                "pass",
            )
            self.assertEqual(
                recovered["expected_postconditions"][0]["severity"],
                "critical",
            )


if __name__ == "__main__":
    unittest.main()
