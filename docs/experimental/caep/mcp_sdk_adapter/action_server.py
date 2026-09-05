from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from common import read_json, sha256_json, write_json

mcp = FastMCP("caep-payment-action", json_response=True)
LEDGER_PATH: Path | None = None


def ledger_path() -> Path:
    if LEDGER_PATH is None:
        raise RuntimeError("ledger path is not configured")
    return LEDGER_PATH


@mcp.tool()
def observe_order(order_id: str) -> dict[str, Any]:
    """Observe whether an order currently has a successful payment."""
    ledger = read_json(ledger_path())
    successful = [
        item
        for item in ledger["payments"]
        if item["order_id"] == order_id and item["status"] == "succeeded"
    ]
    observation = {
        "order_id": order_id,
        "reported_payment_status": "paid" if successful else "unpaid",
        "successful_payment_count": len(successful),
        "ledger_digest": sha256_json(ledger),
    }
    observation["observation_digest"] = sha256_json(observation)
    return observation


@mcp.tool()
def create_payment(
    order_id: str,
    payment_id: str,
    observation_digest: str,
) -> dict[str, Any]:
    """Create one payment using a previously observed state digest."""
    if len(observation_digest) != 64:
        raise ValueError("observation_digest must be a SHA-256 hex digest")
    ledger = read_json(ledger_path())
    if any(item["payment_id"] == payment_id for item in ledger["payments"]):
        raise ValueError(f"duplicate payment_id: {payment_id}")
    payment = {
        "payment_id": payment_id,
        "order_id": order_id,
        "status": "succeeded",
    }
    ledger["payments"].append(payment)
    write_json(ledger_path(), ledger)
    return {
        "tool": "create_payment",
        "status": "succeeded",
        "payment": payment,
        "observation_digest": observation_digest,
        "ledger_digest_after": sha256_json(ledger),
    }


@mcp.tool()
def cancel_payment(payment_id: str) -> dict[str, Any]:
    """Cancel exactly one payment as a compensating action."""
    ledger = read_json(ledger_path())
    matches = [item for item in ledger["payments"] if item["payment_id"] == payment_id]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one payment {payment_id}")
    matches[0]["status"] = "cancelled"
    write_json(ledger_path(), ledger)
    return {
        "tool": "cancel_payment",
        "status": "succeeded",
        "payment_id": payment_id,
        "ledger_digest_after": sha256_json(ledger),
    }


def main() -> None:
    global LEDGER_PATH
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    args = parser.parse_args()
    LEDGER_PATH = args.ledger.resolve()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
