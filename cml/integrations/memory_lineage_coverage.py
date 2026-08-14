"""Deterministic coverage metric for derived-memory lineage verification.

The metric measures whether a system can actually verify the lineage of records
known to be derived. It intentionally does not measure whether those records are
currently valid. A superseded, retired, erased, or digest-changed parent can be
fully *verifiable* even though it forces the derived memory to REVALIDATE.
"""

from __future__ import annotations

from dataclasses import dataclass

from cml.integrations.memory_applicability import LINEAGE_STATES, SHA256_HEX


@dataclass(frozen=True)
class LineageCoverageDependency:
    """Observed verification material for one declared lineage dependency."""

    dependency_id: str
    state: str | None
    expected_digest: str | None = None
    observed_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.dependency_id, str) or not self.dependency_id.strip():
            raise ValueError("dependency_id must be a non-empty string")
        if self.state is not None and (
            not isinstance(self.state, str) or not self.state.strip()
        ):
            raise ValueError("state must be a non-empty string or None")
        for label, value in (
            ("expected_digest", self.expected_digest),
            ("observed_digest", self.observed_digest),
        ):
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{label} must be a string or None")


@dataclass(frozen=True)
class LineageCoverageRecord:
    """One record in the enumerable population used by the coverage metric.

    ``is_derived`` is explicit so a store can include direct/source records in
    the same scan without accidentally putting them in the denominator.
    """

    record_id: str
    is_derived: bool
    dependencies: tuple[LineageCoverageDependency, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.record_id, str) or not self.record_id.strip():
            raise ValueError("record_id must be a non-empty string")
        if not isinstance(self.is_derived, bool):
            raise TypeError("is_derived must be boolean")

        dependencies = tuple(self.dependencies)
        if not all(
            isinstance(dependency, LineageCoverageDependency)
            for dependency in dependencies
        ):
            raise TypeError(
                "dependencies must contain only LineageCoverageDependency values"
            )
        # Snapshot so later mutation of a caller-supplied mutable list cannot
        # change the coverage evidence this record certifies.
        object.__setattr__(self, "dependencies", dependencies)


@dataclass(frozen=True)
class LineageCoverageGap:
    record_id: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class LineageVerificationCoverage:
    """Measured record-level lineage verification coverage."""

    coverage: float | None
    eligible_derived_records: int
    verified_derived_records: int
    uncovered_derived_records: int
    undefined_reason: str | None
    gaps: tuple[LineageCoverageGap, ...]


def _digest_is_verifiable(value: str | None) -> bool:
    return value is not None and bool(SHA256_HEX.fullmatch(value))


def lineage_coverage_gaps(
    record: LineageCoverageRecord,
) -> tuple[str, ...]:
    """Return reasons a known-derived record cannot be lineage-verified.

    State is deliberately evaluated before digest continuity. Once a dependency
    is observed as superseded, retired, or erased, that state is already a
    decisive lineage observation; an erased parent does not become
    ``unverifiable`` merely because its current digest is absent.
    """

    if not record.is_derived:
        return ()

    if not record.dependencies:
        return ("lineage_undeclared",)

    reasons: list[str] = []
    seen: set[str] = set()

    for dependency in record.dependencies:
        dependency_id = dependency.dependency_id

        if dependency_id in seen:
            reasons.append(f"lineage_duplicate:{dependency_id}")
            continue
        seen.add(dependency_id)

        if dependency.state is None:
            reasons.append(f"lineage_state_unobserved:{dependency_id}")
            continue

        if dependency.state not in LINEAGE_STATES:
            reasons.append(
                f"lineage_state_unknown:{dependency_id}:{dependency.state}"
            )
            continue

        # A recognized dead state is itself a complete verification result for
        # applicability. Digest continuity is not required after invalidation.
        if dependency.state != "active":
            continue

        if not _digest_is_verifiable(dependency.expected_digest):
            reasons.append(f"lineage_expected_digest_unverifiable:{dependency_id}")
        if not _digest_is_verifiable(dependency.observed_digest):
            reasons.append(f"lineage_observed_digest_unverifiable:{dependency_id}")

    return tuple(sorted(reasons))


def measure_lineage_verification_coverage(
    records: tuple[LineageCoverageRecord, ...],
    *,
    derived_population_enumerable: bool = True,
) -> LineageVerificationCoverage:
    """Measure the fraction of known-derived records whose lineage is checkable.

    Denominator:
        every record in the supplied enumerable population with ``is_derived``.
        A derived record with no declared dependency edges remains in the
        denominator and is uncovered; missing lineage metadata must not improve
        the score by disappearing from measurement.

    Numerator:
        derived records for which every declared dependency yields a decisive
        lineage observation. Active parents require verifiable expected and
        observed SHA-256 digests. Recognized non-active states are decisive on
        state alone. Digest equality is *not* required: a detected mismatch is a
        successful verification that should later drive REVALIDATE.

    ``coverage`` is ``None`` when the derived-record population cannot be
    enumerated, or when the enumerable population contains no derived records.
    Those states must not be reported as 0.0.
    """

    if not isinstance(derived_population_enumerable, bool):
        raise TypeError("derived_population_enumerable must be boolean")

    # Duplicate record ids would count the same record twice (or attach the
    # same identity to two different coverage states) after the is_derived
    # filter. Reject the population before any filtering; never deduplicate
    # silently.
    seen_record_ids: set[str] = set()
    for record in records:
        if record.record_id in seen_record_ids:
            raise ValueError(
                f"duplicate record_id in population: {record.record_id}"
            )
        seen_record_ids.add(record.record_id)

    if not derived_population_enumerable:
        return LineageVerificationCoverage(
            coverage=None,
            eligible_derived_records=0,
            verified_derived_records=0,
            uncovered_derived_records=0,
            undefined_reason="derived_population_unenumerable",
            gaps=(),
        )

    eligible = tuple(record for record in records if record.is_derived)
    if not eligible:
        return LineageVerificationCoverage(
            coverage=None,
            eligible_derived_records=0,
            verified_derived_records=0,
            uncovered_derived_records=0,
            undefined_reason="no_eligible_derived_records",
            gaps=(),
        )

    gaps: list[LineageCoverageGap] = []
    for record in eligible:
        reasons = lineage_coverage_gaps(record)
        if reasons:
            gaps.append(LineageCoverageGap(record.record_id, reasons))

    gaps.sort(key=lambda gap: gap.record_id)
    uncovered = len(gaps)
    verified = len(eligible) - uncovered

    return LineageVerificationCoverage(
        coverage=verified / len(eligible),
        eligible_derived_records=len(eligible),
        verified_derived_records=verified,
        uncovered_derived_records=uncovered,
        undefined_reason=None,
        gaps=tuple(gaps),
    )
