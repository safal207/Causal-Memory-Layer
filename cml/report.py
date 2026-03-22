"""
cml.report — Audit report generation

Produces human-readable (Markdown) and machine-readable (JSON) reports
from AuditResult objects.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .audit import AuditResult, Finding, Severity
from .record import CausalRecord
from .chain import reconstruct_chain


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def to_json(result: AuditResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

_SEV_EMOJI = {
    Severity.OK:   "✅",
    Severity.WARN: "⚠️",
    Severity.FAIL: "🔴",
}


def to_markdown(
    result: AuditResult,
    title: str = "vCML Audit Report",
    log_path: Optional[str] = None,
    index: Optional[dict[str, CausalRecord]] = None,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# {title}",
        "",
        f"**Generated:** {now}",
    ]
    if log_path:
        lines.append(f"**Log:** `{log_path}`")
    lines += [
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total records | {result.total} |",
        f"| Failures | {result.failures} |",
        f"| Warnings | {result.warnings} |",
        f"| Overall | {'**PASS**' if result.passed() else '**FAIL**'} |",
        "",
    ]

    if not result.findings:
        lines += ["## Findings", "", "_No issues found._", ""]
        return "\n".join(lines)

    # Group by severity
    fails  = [f for f in result.findings if f.severity == Severity.FAIL]
    warns  = [f for f in result.findings if f.severity == Severity.WARN]

    if fails:
        lines += ["## Failures", ""]
        for f in fails:
            lines += _finding_block(f, index)

    if warns:
        lines += ["## Warnings", ""]
        for f in warns:
            lines += _finding_block(f, index)

    return "\n".join(lines)


def _finding_block(
    finding: Finding,
    index: Optional[dict[str, CausalRecord]],
) -> list[str]:
    emoji = _SEV_EMOJI.get(finding.severity, "")
    lines = [
        f"### {emoji} `{finding.code}`",
        "",
        f"- **Record:** `{finding.record_id}`",
        f"- **Message:** {finding.message}",
    ]

    if finding.chain_ids:
        lines.append(f"- **Related records:** {', '.join(f'`{i}`' for i in finding.chain_ids)}")

    if index and finding.record_id in index:
        chain = reconstruct_chain(finding.record_id, index)
        if len(chain) > 1:
            lines += ["", "**Reconstructed chain:**", "```"]
            for r in chain:
                arrow = "→ " if r.id != chain[0].id else "  "
                lines.append(
                    f"{arrow}[{r.id[:8]}] {r.action:8s} "
                    f"| permitted_by={r.permitted_by} "
                    f"| parent={r.parent_cause or 'null'}"
                )
            lines.append("```")

    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Plain text summary (for terminal)
# ---------------------------------------------------------------------------

def to_text(result: AuditResult) -> str:
    lines = [
        f"CML Audit: {result.total} records | "
        f"FAIL={result.failures} WARN={result.warnings} OK={result.ok}",
        "Status: " + ("PASS" if result.passed() else "FAIL"),
    ]
    for f in result.findings:
        lines.append(f"  [{f.severity}] {f.code} @ {f.record_id}: {f.message}")
    return "\n".join(lines)
