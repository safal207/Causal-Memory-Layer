"""Independent successful-read object bindings for exact CML reconciliation.

Read identity answers *which read boundary completed*. Object identity adds the
next question: *which kernel file object did that read target at syscall entry?*

The reference Linux witness uses a local ``(superblock device, inode)`` pair
captured by the kernel at ``sys_enter_read``. This is a correlation identity,
not a content hash, cryptographic identity, stable cross-host identifier, or
permanent pathname.
"""

from __future__ import annotations

from dataclasses import dataclass

from cml.external_read_witness import ExternalReadIdentityWitness


@dataclass(frozen=True)
class ExternalReadObjectBinding:
    """One successful external read bound to one kernel object identity."""

    read_id: str
    object_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.read_id, str) or not self.read_id.strip():
            raise ValueError("read_id must be a non-empty string")
        if not isinstance(self.object_id, str) or not self.object_id.strip():
            raise ValueError("object_id must be a non-empty string")


@dataclass(frozen=True)
class ExternalReadObjectWitness:
    """Exact successful-read to object bindings from an independent witness."""

    source_id: str
    scope_id: str
    completed_bindings: tuple[ExternalReadObjectBinding, ...]
    available: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            raise ValueError("source_id must be a non-empty string")
        if not isinstance(self.scope_id, str) or not self.scope_id.strip():
            raise ValueError("scope_id must be a non-empty string")
        if not isinstance(self.completed_bindings, tuple):
            raise TypeError("completed_bindings must be a tuple")
        if not isinstance(self.available, bool):
            raise TypeError("available must be boolean")
        if not self.available and self.completed_bindings:
            raise ValueError("unavailable object witness cannot carry completed_bindings")

        seen_read_ids: set[str] = set()
        for binding in self.completed_bindings:
            if not isinstance(binding, ExternalReadObjectBinding):
                raise TypeError(
                    "completed_bindings must contain ExternalReadObjectBinding values"
                )
            if binding.read_id in seen_read_ids:
                raise ValueError(f"duplicate completed read_id: {binding.read_id}")
            seen_read_ids.add(binding.read_id)

    @property
    def reads_count(self) -> int:
        return len(self.completed_bindings)

    @property
    def completed_read_ids(self) -> tuple[str, ...]:
        return tuple(binding.read_id for binding in self.completed_bindings)

    def as_identity_witness(self) -> ExternalReadIdentityWitness:
        """Project object-bound evidence into the per-read identity contract."""

        return ExternalReadIdentityWitness(
            source_id=self.source_id,
            scope_id=self.scope_id,
            completed_read_ids=self.completed_read_ids if self.available else (),
            available=self.available,
        )
