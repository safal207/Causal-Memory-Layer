#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from common import read_json, sha256_json, write_json


def create_payment(
    ledger_path: Path,
    observation_path: Path,
    payment_id: str,
    output_path: Path,
) -> None:
    """Create one payment from a previously produced observation."""
    ledger = read_json(ledger_path)
    observation = read_json(observation_path)
    if observation["reported_payment_status"] != "unpaid":
        raise ValueError("observation does not authorize payment creation")
    if any(item["payment_id"] == payment_id for item in ledger["payments"]):
        raise ValueError(f"duplicate payment_id: {payment_id}")

    payment = {
        "payment_id": payment_id,
        "order_id": observation["order_id"],
        "status": "succeeded",
    }
    ledger["payments"].append(payment)
    write_json(ledger_path, ledger)

    outcome = {
        "producer": "urn:mcp-server:payment-writer",
        "tool": "create_payment",
        "payment": payment,
        "observation_digest": observation["observation_digest"],
        "ledger_digest_after": sha256_json(ledger),
    }
    outcome["outcome_digest"] = sha256_json(outcome)
    write_json(output_path, outcome)


def cancel_payment(
    ledger_path: Path,
    payment_id: str,
    output_path: Path,
) -> None:
    """Cancel exactly one payment as a compensating action."""
    ledger = read_json(ledger_path)
    matches = [
        item for item in ledger["payments"] if item["payment_id"] == payment_id
    ]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one payment {payment_id}")
    matches[0]["status"] = "cancelled"
    write_json(ledger_path, ledger)

    outcome = {
        "producer": "urn:mcp-server:payment-writer",
        "tool": "cancel_payment",
        "payment_id": payment_id,
        "status": "succeeded",
        "ledger_digest_after": sha256_json(ledger),
    }
    outcome["outcome_digest"] = sha256_json(outcome)
    write_json(output_path, outcome)


def main() -> int:
    """Run the action-server command-line adapter."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--ledger", type=Path, required=True)
    create.add_argument("--observation", type=Path, required=True)
    create.add_argument("--payment-id", required=True)
    create.add_argument("--output", type=Path, required=True)

    cancel = subparsers.add_parser("cancel")
    cancel.add_argument("--ledger", type=Path, required=True)
    cancel.add_argument("--payment-id", required=True)
    cancel.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    if args.command == "create":
        create_payment(
            args.ledger,
            args.observation,
            args.payment_id,
            args.output,
        )
    else:
        cancel_payment(args.ledger, args.payment_id, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
