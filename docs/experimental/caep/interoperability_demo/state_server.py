#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from common import read_json, sha256_json, write_json


def observe(ledger_path: Path, order_id: str, output_path: Path) -> None:
    """Produce a portable order-state observation artifact."""
    ledger = read_json(ledger_path)
    payments = [
        item for item in ledger["payments"] if item["order_id"] == order_id
    ]
    succeeded = [item for item in payments if item["status"] == "succeeded"]
    observation = {
        "producer": "urn:mcp-server:state-reader",
        "order_id": order_id,
        "reported_payment_status": "paid" if succeeded else "unpaid",
        "successful_payment_count": len(succeeded),
        "ledger_digest": sha256_json(ledger),
    }
    observation["observation_digest"] = sha256_json(observation)
    write_json(output_path, observation)


def main() -> int:
    """Run the state-server command-line adapter."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--order-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    observe(args.ledger, args.order_id, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
