"""
Causal chain reconstruction.
Given a record ID and a log, follows parent_cause links to the root.
"""
from __future__ import annotations

from typing import Any


def reconstruct_chain(records: list[dict], target_id: str) -> dict:
    """
    Reconstruct the causal chain ending at target_id.

    Returns a dict with:
      target_id: str
      chain: list of records from root to target (in order)
      has_gap: bool — True when the chain terminates with a gap (not a root_event)
      gap_note: str | None
      r3_context: dict | None — filled when a SECRET access is NOT in the chain
        but shares the same PID as the target
    """
    ROOT_PREFIX = "root_event:"
    id_to_record: dict[str, Any] = {
        rec.get("id"): rec for rec in records if rec.get("id")
    }

    if target_id not in id_to_record:
        return {
            "target_id": target_id,
            "chain": [],
            "has_gap": True,
            "gap_note": f"Record '{target_id}' not found in log",
            "r3_context": None,
        }

    # Walk backwards from target to root
    chain_reversed: list[dict] = []
    visited: set[str] = set()
    current_id: str | None = target_id
    has_gap = False
    gap_note: str | None = None

    while current_id:
        if current_id in visited:
            gap_note = f"Cycle detected at '{current_id}' — chain truncated"
            has_gap = True
            break
        visited.add(current_id)
        rec = id_to_record.get(current_id)
        if not rec:
            gap_note = f"Record '{current_id}' referenced by parent_cause is missing from log"
            has_gap = True
            break
        chain_reversed.append(rec)
        parent_cause = rec.get("parent_cause")
        if parent_cause is None:
            permitted_by = rec.get("permitted_by", "")
            if not (isinstance(permitted_by, str) and permitted_by.startswith(ROOT_PREFIX)):
                has_gap = True
                if permitted_by == "unobserved_parent":
                    gap_note = (
                        f"Chain has a gap at '{current_id}': "
                        "parent is unobserved (permitted_by: unobserved_parent)"
                    )
                else:
                    gap_note = (
                        f"Chain terminates at '{current_id}' with parent_cause=null "
                        f"(permitted_by: '{permitted_by}') — neither a root nor a marked gap"
                    )
            break
        current_id = parent_cause

    chain = list(reversed(chain_reversed))
    chain_ids = {r.get("id") for r in chain}

    # Check for R3 context: SECRET access by the same process not in chain
    target_rec = id_to_record[target_id]
    target_action = target_rec.get("action", "")
    target_pid = target_rec.get("actor", {}).get("pid")
    r3_context: dict | None = None

    if target_action in ("connect", "send") and target_pid is not None:
        for rec in records:
            if rec.get("actor", {}).get("pid") != target_pid:
                continue
            rec_action = rec.get("action", "")
            rec_obj = rec.get("object")
            is_secret = (
                isinstance(rec_obj, dict)
                and (
                    rec_obj.get("classification") == "SECRET"
                    or str(rec_obj.get("path", "")).startswith("/secrets/")
                )
            )
            if rec_action in ("open", "read") and is_secret:
                if rec.get("id") not in chain_ids:
                    r3_context = {
                        "secret_record": rec,
                        "note": (
                            f"SECRET access ({rec.get('id')} {rec_action} "
                            f"{rec_obj.get('path', '?') if isinstance(rec_obj, dict) else rec_obj})"
                            " by same process is NOT causally linked to this NET_OUT record"
                        ),
                    }
                    break

    return {
        "target_id": target_id,
        "chain": chain,
        "has_gap": has_gap,
        "gap_note": gap_note,
        "r3_context": r3_context,
    }
