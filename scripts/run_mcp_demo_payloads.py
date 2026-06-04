from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from cml.integrations.mcp import core

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PAYLOAD = ROOT / "examples" / "mcp" / "audit_trace_missing_parent.json"
CAUSE_BAND_PAYLOAD = ROOT / "examples" / "mcp" / "evaluate_cause_band_degrading.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _print_section(title: str, payload: dict[str, Any]) -> None:
    print(f"\n## {title}")
    print(json.dumps(payload, indent=2, sort_keys=True))


def run_demo() -> dict[str, Any]:
    """Run the MCP demo payloads through the MCP core tool logic."""
    health_result = core.health()
    audit_result = core.audit_trace(_load_json(AUDIT_PAYLOAD))
    cause_band_result = core.evaluate_cause_band(_load_json(CAUSE_BAND_PAYLOAD))
    return {
        "health": health_result,
        "audit_trace": audit_result,
        "evaluate_cause_band": cause_band_result,
    }


def main() -> int:
    result = run_demo()
    _print_section("health", result["health"])
    _print_section("audit_trace", result["audit_trace"])
    _print_section("evaluate_cause_band", result["evaluate_cause_band"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
