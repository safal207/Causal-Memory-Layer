"""
Audit engine implementing CML rules R1–R4 (v0.5.1).
See vcml/audit.md for rule semantics.
"""
from __future__ import annotations

from typing import Any


def _is_secret(obj: Any) -> bool:
    """Return True if the object field refers to a SECRET-classified resource."""
    if isinstance(obj, dict):
        if obj.get("classification") == "SECRET":
            return True
        path = obj.get("path", "")
        return path.startswith("/secrets/") or path.endswith((".key", ".pem"))
    return False


def _is_net_out(action: str) -> bool:
    return action in ("connect", "send")


def _ancestor_ids(record_id: str, id_to_record: dict[str, Any]) -> set[str]:
    """Follow parent_cause links backwards and return the set of all ancestor IDs
    (including record_id itself)."""
    visited: set[str] = set()
    current: str | None = record_id
    while current and current not in visited:
        visited.add(current)
        rec = id_to_record.get(current)
        if not rec:
            break
        current = rec.get("parent_cause")
    return visited


def audit(records: list[dict], _config: dict | None = None) -> dict:
    """
    Run audit rules R1–R4 on an ordered list of causal records.

    Returns a dict with:
      summary: {total, ok, warn, fail, passed}
      findings: list of finding objects
    """
    ROOT_PREFIX = "root_event:"

    # Build id → record and id → 1-based line number
    id_to_record: dict[str, Any] = {}
    id_to_line: dict[str, int] = {}
    for i, rec in enumerate(records):
        rid = rec.get("id")
        if rid:
            id_to_record[rid] = rec
            id_to_line[rid] = i + 1

    # Track SECRET accesses per process: pid → [record_id, ...]
    pid_secret_records: dict[int, list[str]] = {}

    findings: list[dict] = []

    for rec in records:
        rid: str = rec.get("id", "")
        actor: dict = rec.get("actor", {})
        pid: int | None = actor.get("pid")
        action: str = rec.get("action", "")
        obj: Any = rec.get("object")
        parent_cause: str | None = rec.get("parent_cause")
        permitted_by: str = rec.get("permitted_by", "")
        line: int | None = id_to_line.get(rid)

        rec_findings: list[dict] = []

        # R1 — Reference Integrity
        if parent_cause is not None:
            if parent_cause not in id_to_record:
                rec_findings.append({
                    "rule": "R1",
                    "code": "CML-AUDIT-R1-MISSING_PARENT",
                    "severity": "FAIL",
                    "record_id": rid,
                    "line": line,
                    "message": (
                        f"parent_cause '{parent_cause}' references a record"
                        " that does not exist in this log"
                    ),
                })

        # R2 — Gap Marking Consistency
        if parent_cause is None:
            is_root = isinstance(permitted_by, str) and permitted_by.startswith(ROOT_PREFIX)
            is_marked_gap = permitted_by == "unobserved_parent"
            if not is_root and not is_marked_gap:
                rec_findings.append({
                    "rule": "R2",
                    "code": "CML-AUDIT-R2-GAP_NOT_MARKED",
                    "severity": "WARN",
                    "record_id": rid,
                    "line": line,
                    "message": (
                        f"parent_cause is null but permitted_by ('{permitted_by}') is"
                        " neither 'unobserved_parent' nor a 'root_event:' label"
                    ),
                })

        # Track SECRET accesses (open/read of a SECRET object)
        if action in ("open", "read") and _is_secret(obj) and pid is not None:
            pid_secret_records.setdefault(pid, []).append(rid)

        # R3 — SECRET → NET_OUT causal chain
        if _is_net_out(action) and pid is not None:
            secret_recs = pid_secret_records.get(pid, [])
            if secret_recs:
                chain = _ancestor_ids(rid, id_to_record)
                for secret_rid in secret_recs:
                    if secret_rid not in chain:
                        secret_rec = id_to_record[secret_rid]
                        secret_obj = secret_rec.get("object", {})
                        secret_path = (
                            secret_obj.get("path", "?")
                            if isinstance(secret_obj, dict)
                            else str(secret_obj)
                        )
                        net_desc = (
                            f"{obj.get('addr', '?')}:{obj.get('port', '?')}"
                            if isinstance(obj, dict)
                            else str(obj)
                        )
                        rec_findings.append({
                            "rule": "R3",
                            "code": "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN",
                            "severity": "FAIL",
                            "record_id": rid,
                            "line": line,
                            "message": (
                                f"NET_OUT ({action} to {net_desc}) has no causal chain"
                                f" back to SECRET access ({secret_rid} read {secret_path})"
                            ),
                        })
                        break  # one finding per NET_OUT record

        # R4 — Root Event Identification
        if parent_cause is None:
            is_root = isinstance(permitted_by, str) and permitted_by.startswith(ROOT_PREFIX)
            is_marked_gap = permitted_by == "unobserved_parent"
            if not is_root and not is_marked_gap:
                rec_findings.append({
                    "rule": "R4",
                    "code": "CML-AUDIT-R4-AMBIGUOUS_ROOT",
                    "severity": "WARN",
                    "record_id": rid,
                    "line": line,
                    "message": (
                        f"Record has parent_cause=null but is neither a root_event"
                        f" nor marked as unobserved_parent (permitted_by: '{permitted_by}')"
                    ),
                })

        if rec_findings:
            findings.extend(rec_findings)
        else:
            findings.append({
                "rule": "OK",
                "code": "OK",
                "severity": "OK",
                "record_id": rid,
                "line": line,
                "message": "All rules passed",
            })

    fail_count = sum(1 for f in findings if f["severity"] == "FAIL")
    warn_count = sum(1 for f in findings if f["severity"] == "WARN")
    ok_count = sum(1 for f in findings if f["severity"] == "OK")

    return {
        "summary": {
            "total": len(findings),
            "ok": ok_count,
            "warn": warn_count,
            "fail": fail_count,
            "passed": fail_count == 0,
        },
        "findings": findings,
    }
