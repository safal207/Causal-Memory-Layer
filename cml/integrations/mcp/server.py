from __future__ import annotations

import sys
from typing import Any

from . import core

_MISSING_MCP_EXTRA_MESSAGE = """\
The CML MCP server requires the optional MCP dependency.

Install CML with MCP support:

  pip install "causal-memory-layer[mcp]"

For local development from the repository root:

  pip install -e ".[mcp]"
"""

try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError as exc:
    if exc.name != "mcp":
        raise
    FastMCP = None  # type: ignore[assignment]


if FastMCP is not None:
    mcp = FastMCP("cml-agent-audit")

    @mcp.tool()
    def health() -> dict[str, Any]:
        """Return basic CML MCP integration status."""
        return core.health()

    @mcp.tool()
    def audit_trace(payload: Any) -> dict[str, Any]:
        """Audit JSON-compatible CML records or an agent_trace payload."""
        return core.audit_trace(payload)

    @mcp.tool()
    def evaluate_cause_band(payload: dict[str, Any]) -> dict[str, Any]:
        """Evaluate a Cause Band fixture or payload containing cause_band_sidecar."""
        return core.evaluate_cause_band(payload)
else:
    mcp = None


def main() -> None:
    if mcp is None:
        print(_MISSING_MCP_EXTRA_MESSAGE, file=sys.stderr)
        raise SystemExit(2)
    mcp.run()


if __name__ == "__main__":
    main()
