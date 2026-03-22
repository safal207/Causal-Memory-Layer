"""
cml.chain — Causal chain reconstruction

Provides utilities to walk parent_cause links and reconstruct full
causal chains from an indexed log.
"""

from __future__ import annotations

from typing import Optional
from .record import CausalRecord


# ---------------------------------------------------------------------------
# Chain reconstruction
# ---------------------------------------------------------------------------

def reconstruct_chain(
    record_id: str,
    index: dict[str, CausalRecord],
    max_depth: int = 256,
) -> list[CausalRecord]:
    """
    Walk parent_cause links from `record_id` to the root.

    Returns the chain ordered root-first (oldest → newest).
    Stops at max_depth to prevent infinite loops on corrupt logs.
    """
    chain: list[CausalRecord] = []
    visited: set[str] = set()
    current_id: Optional[str] = record_id

    while current_id is not None:
        if current_id in visited:
            break  # cycle guard
        if len(chain) >= max_depth:
            break
        record = index.get(current_id)
        if record is None:
            break
        chain.append(record)
        visited.add(current_id)
        current_id = record.parent_cause

    chain.reverse()
    return chain


def find_root(
    record_id: str,
    index: dict[str, CausalRecord],
) -> Optional[CausalRecord]:
    """Return the root CausalRecord for the given record's chain."""
    chain = reconstruct_chain(record_id, index)
    return chain[0] if chain else None


# ---------------------------------------------------------------------------
# Chain path check
# ---------------------------------------------------------------------------

def has_path(
    from_id: str,
    to_id: str,
    index: dict[str, CausalRecord],
    max_depth: int = 256,
) -> bool:
    """
    Return True if `to_id` is an ancestor of `from_id` via parent_cause links.

    Public utility for point-to-point reachability queries.  The audit engine
    uses ancestors() + set intersection for batch checks (O(chain_depth) vs
    O(S × chain_depth)), but has_path is useful when testing a single pair.
    """
    visited: set[str] = set()
    start = index.get(from_id)
    if start is None:
        return False
    current: Optional[str] = start.parent_cause

    depth = 0
    while current is not None and depth < max_depth:
        if current == to_id:
            return True
        if current in visited:
            return False
        visited.add(current)
        record = index.get(current)
        if record is None:
            return False
        current = record.parent_cause
        depth += 1
    return False


# ---------------------------------------------------------------------------
# Process context grouping
# ---------------------------------------------------------------------------

def group_by_pid(records: list[CausalRecord]) -> dict[int, list[CausalRecord]]:
    """Group records by actor.pid, sorted by timestamp."""
    groups: dict[int, list[CausalRecord]] = {}
    for r in sorted(records, key=lambda x: x.timestamp):
        pid = r.actor.pid
        groups.setdefault(pid, []).append(r)
    return groups


def ancestors(
    record_id: str,
    index: dict[str, CausalRecord],
) -> set[str]:
    """Return the set of all ancestor ids for a record."""
    chain = reconstruct_chain(record_id, index)
    return {r.id for r in chain}
