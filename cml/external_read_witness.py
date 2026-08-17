"""Independent read-witness contract for memory admissibility checks.

The witness is intentionally separate from the memory ledger it validates. A
ledger can report what it observed, but it cannot prove that it would have
observed events that its own collector missed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExternalReadWitness:
    """Summary produced by an observation path independent of the memory store."""

    source_id: str
    scope_id: str
    reads_count: int
    available: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            raise ValueError("source_id must be a non-empty string")
        if not isinstance(self.scope_id, str) or not self.scope_id.strip():
            raise ValueError("scope_id must be a non-empty string")
        if not isinstance(self.reads_count, int) or isinstance(self.reads_count, bool):
            raise TypeError("reads_count must be an integer")
        if self.reads_count < 0:
            raise ValueError("reads_count must be non-negative")
        if not isinstance(self.available, bool):
            raise TypeError("available must be boolean")
