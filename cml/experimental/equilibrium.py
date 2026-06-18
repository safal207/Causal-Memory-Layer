"""Experimental causal equilibrium evaluation.

A causal graph can be structurally valid while still presenting an incomplete
or one-sided decision context. This module evaluates whether a decision
snapshot has enough resolved causal material to be described as balanced,
unstable, or indeterminate.

The evaluator is read-only. It does not judge decision correctness, enforce
policy, block actions, or assign moral weight to evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping


class EquilibriumState(str, Enum):
    """Deterministic state returned by :func:`evaluate_causal_equilibrium`."""

    BALANCED = "BALANCED"
    UNSTABLE = "UNSTABLE"
    INDETERMINATE = "INDETERMINATE"


class EquilibriumSeverity(str, Enum):
    """Severity of an equilibrium finding."""

    WARN = "WARN"
    FAIL = "FAIL"


_EQUILIBRIUM_SEVERITY_RANK = {
    EquilibriumSeverity.FAIL: 0,
    EquilibriumSeverity.WARN: 1,
}


@dataclass(frozen=True)
class CausalEquilibriumSnapshot:
    """Material references used to evaluate one decision checkpoint.

    ``supporting_refs`` and ``counter_refs`` record material that supports or
    challenges the proposed action. ``recalled_memory_refs`` captures explicit
    cross-session influence. ``unresolved_refs`` records references that the
    producer already knows are unresolved.

    When memory consolidation is involved, ``consolidation_source_refs`` lists
    provenance references entering the consolidation step and
    ``consolidation_preserved_refs`` lists the references retained by the
    resulting summary or cluster.
    """

    action_ref: str
    supporting_refs: tuple[str, ...] = ()
    counter_refs: tuple[str, ...] = ()
    recalled_memory_refs: tuple[str, ...] = ()
    unresolved_refs: tuple[str, ...] = ()
    consolidation_source_refs: tuple[str, ...] = ()
    consolidation_preserved_refs: tuple[str, ...] = ()
    require_counterevidence: bool = False
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.action_ref, str) or not self.action_ref:
            raise ValueError("action_ref must be a non-empty string")

        for field_name in (
            "supporting_refs",
            "counter_refs",
            "recalled_memory_refs",
            "unresolved_refs",
            "consolidation_source_refs",
            "consolidation_preserved_refs",
        ):
            refs = getattr(self, field_name)
            if not isinstance(refs, tuple):
                raise TypeError(f"{field_name} must be a tuple of strings")
            if any(not isinstance(ref, str) or not ref for ref in refs):
                raise ValueError(f"{field_name} must contain non-empty strings")
            if len(set(refs)) != len(refs):
                raise ValueError(f"{field_name} must not contain duplicates")


@dataclass(frozen=True)
class EquilibriumFinding:
    """One deterministic causal-equilibrium finding."""

    code: str
    severity: EquilibriumSeverity
    message: str
    refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class CausalEquilibriumResult:
    """Result of one equilibrium evaluation."""

    action_ref: str
    state: EquilibriumState
    findings: tuple[EquilibriumFinding, ...]

    def balanced(self) -> bool:
        return self.state is EquilibriumState.BALANCED


def _missing(refs: Iterable[str], known_refs: set[str]) -> tuple[str, ...]:
    return tuple(sorted(set(refs) - known_refs))


def _finding_sort_key(
    finding: EquilibriumFinding,
) -> tuple[str, int, tuple[str, ...], str]:
    """Return the v1 canonical ordering key for equilibrium findings."""

    return (
        finding.code,
        _EQUILIBRIUM_SEVERITY_RANK[finding.severity],
        tuple(sorted(finding.refs)),
        finding.message,
    )


def evaluate_causal_equilibrium(
    snapshot: CausalEquilibriumSnapshot,
    *,
    known_refs: Iterable[str],
) -> CausalEquilibriumResult:
    """Evaluate a read-only causal equilibrium checkpoint.

    State precedence is deterministic:

    1. any ``FAIL`` finding -> ``UNSTABLE``;
    2. otherwise any ``WARN`` finding -> ``INDETERMINATE``;
    3. otherwise -> ``BALANCED``.

    Findings are emitted in the canonical v1 order:
    ``(code, severity_rank, refs_lexicographic, message)`` where ``FAIL`` has
    rank 0 and ``WARN`` has rank 1.
    """

    known = set(known_refs)
    if any(not isinstance(ref, str) or not ref for ref in known):
        raise ValueError("known_refs must contain non-empty strings")

    findings: list[EquilibriumFinding] = []

    if snapshot.require_counterevidence and not snapshot.counter_refs:
        findings.append(
            EquilibriumFinding(
                code="CML-EQ-01-MISSING_COUNTEREVIDENCE",
                severity=EquilibriumSeverity.WARN,
                message=(
                    "The checkpoint requires counterevidence, but no "
                    "counter_refs were recorded."
                ),
            )
        )

    missing_memories = _missing(snapshot.recalled_memory_refs, known)
    if missing_memories:
        findings.append(
            EquilibriumFinding(
                code="CML-EQ-02-UNRESOLVED_MEMORY_INFLUENCE",
                severity=EquilibriumSeverity.FAIL,
                message=(
                    "One or more recalled memories influencing the action "
                    "cannot be resolved."
                ),
                refs=missing_memories,
            )
        )

    missing_material = _missing(
        snapshot.supporting_refs + snapshot.counter_refs,
        known,
    )
    if missing_material:
        findings.append(
            EquilibriumFinding(
                code="CML-EQ-04-INDETERMINATE_STATE",
                severity=EquilibriumSeverity.WARN,
                message=(
                    "One or more material supporting or counter references "
                    "cannot be resolved."
                ),
                refs=missing_material,
            )
        )

    explicit_unresolved = tuple(sorted(set(snapshot.unresolved_refs)))
    if explicit_unresolved:
        findings.append(
            EquilibriumFinding(
                code="CML-EQ-04-INDETERMINATE_STATE",
                severity=EquilibriumSeverity.WARN,
                message="The producer recorded unresolved causal references.",
                refs=explicit_unresolved,
            )
        )

    lost_provenance = tuple(
        sorted(
            set(snapshot.consolidation_source_refs)
            - set(snapshot.consolidation_preserved_refs)
        )
    )
    if lost_provenance:
        findings.append(
            EquilibriumFinding(
                code="CML-EQ-03-CONSOLIDATION_IMBALANCE",
                severity=EquilibriumSeverity.FAIL,
                message=(
                    "Memory consolidation did not preserve all declared "
                    "provenance references."
                ),
                refs=lost_provenance,
            )
        )

    material_count = (
        len(snapshot.supporting_refs)
        + len(snapshot.counter_refs)
        + len(snapshot.recalled_memory_refs)
    )
    if material_count == 0:
        findings.append(
            EquilibriumFinding(
                code="CML-EQ-04-INDETERMINATE_STATE",
                severity=EquilibriumSeverity.WARN,
                message=(
                    "The checkpoint contains no supporting, counter, or "
                    "recalled-memory references."
                ),
            )
        )

    normalized_findings = [
        EquilibriumFinding(
            code=finding.code,
            severity=finding.severity,
            message=finding.message,
            refs=tuple(sorted(finding.refs)),
        )
        for finding in findings
    ]
    normalized_findings.sort(key=_finding_sort_key)

    severities = {finding.severity for finding in normalized_findings}
    if EquilibriumSeverity.FAIL in severities:
        state = EquilibriumState.UNSTABLE
    elif EquilibriumSeverity.WARN in severities:
        state = EquilibriumState.INDETERMINATE
    else:
        state = EquilibriumState.BALANCED

    return CausalEquilibriumResult(
        action_ref=snapshot.action_ref,
        state=state,
        findings=tuple(normalized_findings),
    )
