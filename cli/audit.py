"""
CLI audit adapter — thin shim over ``cml.audit.AuditEngine``.

This module previously contained a parallel re-implementation of rules
R1–R4 which kept drifting from the SDK engine (cf. the duplicate-finding
bug fixed in PR #57 and the SAST report at
docs/reviews/sast-report-2026-04-24.md).

Now it just converts ``list[dict]`` ↔ the CLI's expected output shape
and delegates rule evaluation to the SDK so there is exactly one source
of truth for audit semantics.
"""
from __future__ import annotations

from cml.audit import AuditConfig, AuditEngine, Severity
from cml.record import CausalRecord


def _code_to_rule(code: str) -> str:
    # "CML-AUDIT-R1-MISSING_PARENT" -> "R1"; falls back to "?" for unknown codes
    parts = code.split("-")
    return parts[2] if len(parts) >= 3 else "?"


def audit(records: list[dict], _config: dict | None = None) -> dict:
    """Run R1–R4 audit on raw record dicts.

    Returns the dict shape ``cli/main.py`` expects:
        {"summary": {total, ok, warn, fail, passed}, "findings": [...]}
    Each finding has ``rule``, ``code``, ``severity``, ``record_id``,
    ``line``, and ``message``. Records that produce no findings are
    represented by a single synthetic ``"rule": "OK"`` entry so the CLI
    can render a per-record status.
    """
    cml_records: list[CausalRecord] = []
    id_to_line: dict[str, int] = {}
    for i, raw in enumerate(records):
        rid = raw.get("id")
        if rid:
            id_to_line[rid] = i + 1
        cml_records.append(CausalRecord.from_dict(raw))

    result = AuditEngine(AuditConfig()).run(cml_records)

    findings_by_record: dict[str, list[dict]] = {}
    for f in result.findings:
        findings_by_record.setdefault(f.record_id, []).append({
            "rule": _code_to_rule(f.code),
            "code": f.code,
            "severity": f.severity,
            "record_id": f.record_id,
            "line": id_to_line.get(f.record_id),
            "message": f.message,
        })

    findings: list[dict] = []
    for rec in cml_records:
        per_rec = findings_by_record.get(rec.id)
        if per_rec:
            findings.extend(per_rec)
        else:
            findings.append({
                "rule": "OK",
                "code": "OK",
                "severity": Severity.OK,
                "record_id": rec.id,
                "line": id_to_line.get(rec.id),
                "message": "All rules passed",
            })

    fail = sum(1 for f in findings if f["severity"] == Severity.FAIL)
    warn = sum(1 for f in findings if f["severity"] == Severity.WARN)
    ok = sum(1 for f in findings if f["severity"] == Severity.OK)
    return {
        "summary": {
            "total": len(findings),
            "ok": ok,
            "warn": warn,
            "fail": fail,
            "passed": fail == 0,
        },
        "findings": findings,
    }
