#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from common import read_json, write_json
from record_builder import build_record

HERE = Path(__file__).resolve().parent


def call(script: str, *args: str) -> None:
    """Run one independent demo participant."""
    subprocess.run(
        [sys.executable, str(HERE / script), *args],
        check=True,
    )


def snapshot(source: Path, destination: Path) -> None:
    """Copy a ledger as deterministic JSON evidence."""
    write_json(destination, read_json(source))


def run_happy(workdir: Path) -> dict:
    """Run one independently verified successful transition."""
    ledger = workdir / "happy-ledger.json"
    observation = workdir / "happy-observation.json"
    before = workdir / "happy-before.json"
    outcome = workdir / "happy-outcome.json"
    after = workdir / "happy-after.json"
    verification = workdir / "happy-verification.json"

    write_json(ledger, {"payments": []})
    call(
        "state_server.py",
        "--ledger",
        str(ledger),
        "--order-id",
        "order-88",
        "--output",
        str(observation),
    )
    snapshot(ledger, before)
    call(
        "action_server.py",
        "create",
        "--ledger",
        str(ledger),
        "--observation",
        str(observation),
        "--payment-id",
        "payment_A",
        "--output",
        str(outcome),
    )
    snapshot(ledger, after)
    call(
        "verifier.py",
        "--ledger",
        str(ledger),
        "--order-id",
        "order-88",
        "--output",
        str(verification),
    )

    record = build_record(
        episode_id="demo_happy_verified",
        workflow_id="demo_happy_workflow",
        status="verified",
        order_id="order-88",
        action_tool="create_payment",
        request_path=observation,
        response_path=outcome,
        verification_path=verification,
        state_before_path=before,
        state_after_path=after,
        started_at="2026-07-29T17:00:01Z",
        completed_at="2026-07-29T17:00:02Z",
        observed_at="2026-07-29T17:00:03Z",
        verified_at="2026-07-29T17:00:04Z",
        verification_verdict="verified",
        verification_result="pass",
        recovery_status="available",
    )
    return {"record": record, "verification": read_json(verification)}


def run_recovery(workdir: Path) -> dict:
    """Run stale-state divergence, containment, and recovery."""
    ledger = workdir / "recovery-ledger.json"
    observation = workdir / "recovery-observation.json"
    before_create = workdir / "recovery-before-create.json"
    create_outcome = workdir / "recovery-create-outcome.json"
    after_create = workdir / "recovery-after-create.json"
    diverged_verification = workdir / "recovery-diverged-verification.json"
    before_cancel = workdir / "recovery-before-cancel.json"
    cancel_outcome = workdir / "recovery-cancel-outcome.json"
    after_cancel = workdir / "recovery-after-cancel.json"
    recovered_verification = workdir / "recovery-final-verification.json"

    write_json(ledger, {"payments": []})
    call(
        "state_server.py",
        "--ledger",
        str(ledger),
        "--order-id",
        "order-88",
        "--output",
        str(observation),
    )

    current = read_json(ledger)
    current["payments"].append(
        {
            "payment_id": "payment_A",
            "order_id": "order-88",
            "status": "succeeded",
        }
    )
    write_json(ledger, current)
    snapshot(ledger, before_create)

    call(
        "action_server.py",
        "create",
        "--ledger",
        str(ledger),
        "--observation",
        str(observation),
        "--payment-id",
        "payment_B",
        "--output",
        str(create_outcome),
    )
    snapshot(ledger, after_create)
    call(
        "verifier.py",
        "--ledger",
        str(ledger),
        "--order-id",
        "order-88",
        "--output",
        str(diverged_verification),
    )

    diverged = build_record(
        episode_id="demo_duplicate_diverged",
        workflow_id="demo_recovery_workflow",
        status="contained",
        order_id="order-88",
        action_tool="create_payment",
        request_path=observation,
        response_path=create_outcome,
        verification_path=diverged_verification,
        state_before_path=before_create,
        state_after_path=after_create,
        started_at="2026-07-29T17:10:02Z",
        completed_at="2026-07-29T17:10:03Z",
        observed_at="2026-07-29T17:10:03Z",
        verified_at="2026-07-29T17:10:04Z",
        verification_verdict="diverged",
        verification_result="fail",
        recovery_status="contained",
    )

    snapshot(ledger, before_cancel)
    call(
        "action_server.py",
        "cancel",
        "--ledger",
        str(ledger),
        "--payment-id",
        "payment_B",
        "--output",
        str(cancel_outcome),
    )
    snapshot(ledger, after_cancel)
    call(
        "verifier.py",
        "--ledger",
        str(ledger),
        "--order-id",
        "order-88",
        "--output",
        str(recovered_verification),
    )

    recovered = build_record(
        episode_id="demo_duplicate_recovered",
        workflow_id="demo_recovery_workflow",
        status="recovered",
        order_id="order-88",
        action_tool="cancel_payment",
        request_path=before_cancel,
        response_path=cancel_outcome,
        verification_path=recovered_verification,
        state_before_path=before_cancel,
        state_after_path=after_cancel,
        started_at="2026-07-29T17:10:05Z",
        completed_at="2026-07-29T17:10:06Z",
        observed_at="2026-07-29T17:10:06Z",
        verified_at="2026-07-29T17:10:07Z",
        verification_verdict="verified",
        verification_result="pass",
        recovery_status="recovered",
        parent=diverged,
    )

    return {
        "diverged_record": diverged,
        "recovered_record": recovered,
        "diverged_verification": read_json(diverged_verification),
        "recovered_verification": read_json(recovered_verification),
    }


def main() -> int:
    """Run both scenarios and write one portable bundle."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(
        prefix="caep-interoperability-"
    ) as temp_dir:
        workdir = Path(temp_dir)
        bundle = {
            "profile": "org.causal-memory-layer.caep.interoperability-demo",
            "transport": "filesystem-json",
            "participants": [
                "urn:mcp-server:state-reader",
                "urn:mcp-server:payment-writer",
                "urn:verifier:independent-ledger-reader",
            ],
            "happy_path": run_happy(workdir),
            "recovery_path": run_recovery(workdir),
        }
        write_json(args.output, bundle)

    print(
        json.dumps(
            {
                "happy": bundle["happy_path"]["verification"]["verdict"],
                "diverged": bundle["recovery_path"]
                ["diverged_verification"]["verdict"],
                "recovered": bundle["recovery_path"]
                ["recovered_verification"]["verdict"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
