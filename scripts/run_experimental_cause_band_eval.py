from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cml.experimental.cause_band import DEFAULT_FIXTURE, evaluate_fixture, load_fixture, render_text


def extract_fixture_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a Cause Band fixture from either a fixture file or example sidecar."""
    sidecar = raw.get("cause_band_sidecar")
    if isinstance(sidecar, dict):
        return sidecar
    return raw


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the experimental Cause Band evaluator over a non-CI fixture."
    )
    parser.add_argument(
        "fixture",
        nargs="?",
        default=str(DEFAULT_FIXTURE),
        help=f"Experimental fixture or example path (default: {DEFAULT_FIXTURE})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Render machine-readable JSON instead of text.",
    )
    args = parser.parse_args()

    raw = load_fixture(Path(args.fixture))
    result = evaluate_fixture(extract_fixture_payload(raw))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
