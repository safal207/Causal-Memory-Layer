#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from common import read_json, sha256_json, write_json


def verify(ledger_path: Path, order_id: str, output_path: Path) -> None:
    """Independently verify the single-successful-payment invariant."""
    ledger = read_json(ledger_path)
    payments = [
        item for item in ledger["payments"] if item["order_id"] == order_id
    ]
    succeeded = [item for item in payments if item["status"] == "succeeded"]
    cancelled = [item for item in payments if item["status"] == "cancelled"]
    result = {
        "producer": "urn:verifier:independent-ledger-reader",
        "order_id": order_id,
        "successful_payment_count": len(succeeded),
        "cancelled_payment_count": len(cancelled),
        "payment_ids": sorted(item["payment_id"] for item in payments),
        "verdict": "verified" if len(succeeded) == 1 else "diverged",
        "ledger_digest": sha256_json(ledger),
    }
    result["verification_digest"] = sha256_json(result)
    write_json(output_path, result)


def main() -> int:
    """Run the independent verifier command-line adapter."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--order-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify(args.ledger, args.order_id, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
