from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from common import read_json, sha256_json

mcp = FastMCP("caep-independent-verifier", json_response=True)
LEDGER_PATH: Path | None = None


def ledger_path() -> Path:
    if LEDGER_PATH is None:
        raise RuntimeError("ledger path is not configured")
    return LEDGER_PATH


@mcp.tool()
def verify_single_payment(order_id: str) -> dict[str, Any]:
    """Independently verify that exactly one payment succeeded for an order."""
    ledger = read_json(ledger_path())
    successful = [
        item
        for item in ledger["payments"]
        if item["order_id"] == order_id and item["status"] == "succeeded"
    ]
    passed = len(successful) == 1
    return {
        "order_id": order_id,
        "verdict": "verified" if passed else "diverged",
        "result": "pass" if passed else "fail",
        "successful_payment_count": len(successful),
        "successful_payment_ids": [item["payment_id"] for item in successful],
        "ledger_digest": sha256_json(ledger),
        "verifier": "urn:mcp-server:independent-ledger-verifier",
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
