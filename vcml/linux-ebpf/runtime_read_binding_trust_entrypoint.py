#!/usr/bin/env python3
"""Trust-root entrypoint for the witness-issued read-binding runtime proof.

The protected workflow invokes this file instead of executing the mutable proof
producer directly. Before dispatch, the entrypoint verifies the exact Git blob
identities of both the pure evaluator and the live BPF harness. Any byte change
to either producer therefore fails closed until the trust root is intentionally
re-pinned.
"""

from __future__ import annotations

from pathlib import Path
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
EVALUATOR = ROOT / "cml/integrations/witness_issued_read_token_runtime.py"
HARNESS = ROOT / "vcml/linux-ebpf/runtime_witness_issued_read_token_proof.py"

EXPECTED_BINDING_EVALUATOR_BLOB = "37f55158058e74a979e656ee4e0c15ce23b4bf4e"
EXPECTED_BINDING_HARNESS_BLOB = "b4b5fd205464563f976eefd4d8d125d0985a5579"


def _git_blob(path: Path) -> str:
    completed = subprocess.run(
        ["git", "hash-object", str(path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown git error"
        raise RuntimeError(f"cannot hash runtime producer {path}: {detail}")
    return completed.stdout.strip().lower()


def verify_runtime_producers() -> None:
    expected = {
        EVALUATOR: EXPECTED_BINDING_EVALUATOR_BLOB,
        HARNESS: EXPECTED_BINDING_HARNESS_BLOB,
    }
    for path, expected_blob in expected.items():
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"runtime producer missing or unsafe: {path}")
        observed = _git_blob(path)
        if observed != expected_blob:
            raise RuntimeError(
                f"runtime producer identity mismatch for {path}: "
                f"observed {observed}, expected {expected_blob}"
            )


def main() -> None:
    verify_runtime_producers()
    sys.argv[0] = str(HARNESS)
    runpy.run_path(str(HARNESS), run_name="__main__")


if __name__ == "__main__":
    main()
