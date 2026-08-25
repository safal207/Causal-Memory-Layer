"""Independent read-witness contracts for memory admissibility checks.

The witness is intentionally separate from the memory ledger it validates. A
ledger can report what it observed, but it cannot prove that it would have
observed events that its own collector missed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExternalReadWitness:
    """Aggregate summary produced independently from the memory store."""

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


@dataclass(frozen=True)
class ExternalReadIdentityWitness:
    """Exact successful-read identities from an independent failure domain.

    ``completed_read_ids`` contains only successful syscall completions. EOF
    (a read returning zero bytes) is a successful completion; failed syscalls
    are intentionally absent because they did not produce readable content.

    The identifiers establish correlation, not global uniqueness or
    cryptographic authenticity. Their producer remains part of the witness
    provenance and must fail independently from the ledger being checked.
    """

    source_id: str
    scope_id: str
    completed_read_ids: tuple[str, ...]
    available: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            raise ValueError("source_id must be a non-empty string")
        if not isinstance(self.scope_id, str) or not self.scope_id.strip():
            raise ValueError("scope_id must be a non-empty string")
        if not isinstance(self.completed_read_ids, tuple):
            raise TypeError("completed_read_ids must be a tuple")
        seen: set[str] = set()
        for read_id in self.completed_read_ids:
            if not isinstance(read_id, str) or not read_id.strip():
                raise ValueError("completed_read_ids must contain non-empty strings")
            if read_id in seen:
                raise ValueError(f"duplicate completed read_id: {read_id}")
            seen.add(read_id)
        if not isinstance(self.available, bool):
            raise TypeError("available must be boolean")
        if not self.available and self.completed_read_ids:
            raise ValueError("unavailable identity witness cannot carry completed_read_ids")

    @property
    def reads_count(self) -> int:
        """Number of independently identified successful read completions."""

        return len(self.completed_read_ids)

    def as_count_witness(self) -> ExternalReadWitness:
        """Project exact identity evidence into the legacy aggregate contract."""

        return ExternalReadWitness(
            source_id=self.source_id,
            scope_id=self.scope_id,
            reads_count=self.reads_count if self.available else 0,
            available=self.available,
        )
