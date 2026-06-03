from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import core

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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
