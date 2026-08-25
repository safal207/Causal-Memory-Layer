"""State-bound identifier population measurements.

Identifier collision/headroom measurements are facts about one exact population,
not timeless authority. This module binds a measurement to the population and
writer-policy state that produced it, preserves historical collision evidence,
and fails closed when that state changes before use.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Iterable


POPULATION_COMMITMENT_FIELDS = ("scope", "population_basis", "key_digest")
IDENTIFIER_MEASUREMENT_PREDICATE = "identifier_collision_headroom"
DEFAULT_POPULATION_BASIS = "lookup_keyspace"


def _non_empty(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def key_digest(key: str) -> str:
    """Return a non-reversible stable identity for one identifier key."""

    _non_empty("key", key)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _commit(payload: object) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class IdentifierKeyRecord:
    key: str
    writer_policy_digest: str | None = None
    writer_policy_epoch: str | None = None

    def __post_init__(self) -> None:
        _non_empty("key", self.key)
        for name in ("writer_policy_digest", "writer_policy_epoch"):
            value = getattr(self, name)
            if value is not None:
                _non_empty(name, value)

    @property
    def key_digest(self) -> str:
        return key_digest(self.key)


@dataclass(frozen=True)
class IdentifierPopulationSnapshot:
    """A complete point-in-time identifier population for one lookup basis/scope."""

    scope: str
    records: tuple[IdentifierKeyRecord, ...]
    complete: bool = True
    population_basis: str = DEFAULT_POPULATION_BASIS

    def __post_init__(self) -> None:
        _non_empty("scope", self.scope)
        _non_empty("population_basis", self.population_basis)
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be boolean")
        keys = [record.key for record in self.records]
        if len(set(keys)) != len(keys):
            raise ValueError("identifier keys must be unique within one population snapshot")

    @property
    def population_count(self) -> int:
        return len(self.records)

    @property
    def population_commitment_fields(self) -> tuple[str, ...]:
        """Declare exactly which fields the population commitment depends on."""

        return POPULATION_COMMITMENT_FIELDS

    @property
    def population_commitment(self) -> str:
        return _commit(
            {
                "scope": self.scope,
                "population_basis": self.population_basis,
                "commitment_fields": self.population_commitment_fields,
                "key_digests": sorted(record.key_digest for record in self.records),
            }
        )

    @property
    def writer_contract_commitment(self) -> str:
        return _commit(
            {
                "scope": self.scope,
                "population_basis": self.population_basis,
                "records": sorted(
                    (
                        record.key_digest,
                        record.writer_policy_digest,
                        record.writer_policy_epoch,
                    )
                    for record in self.records
                ),
            }
        )


@dataclass(frozen=True)
class FoldMeasurement:
    name: str
    verdict: str
    keys_lost: int
    collides_at_length: int | None = None
    headroom_chars: int | None = None
    threshold_population: int | None = None

    def __post_init__(self) -> None:
        _non_empty("name", self.name)
        _non_empty("verdict", self.verdict)
        if self.keys_lost < 0:
            raise ValueError("keys_lost must be non-negative")
        for name in ("collides_at_length", "headroom_chars", "threshold_population"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} must be non-negative when provided")


@dataclass(frozen=True)
class HistoricalKeyLedger:
    """Append-only identity coverage for keys ever observed in one scope."""

    scope: str
    key_digests: tuple[str, ...]
    complete: bool

    def __post_init__(self) -> None:
        _non_empty("scope", self.scope)
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be boolean")
        if any(not isinstance(value, str) or not value.strip() for value in self.key_digests):
            raise ValueError("key_digests must contain only non-empty strings")
        if len(set(self.key_digests)) != len(self.key_digests):
            raise ValueError("historical key digests must be unique")


@dataclass(frozen=True)
class HistoricalCollisionRecord:
    """Sticky evidence that a fold collapsed identifiers in a prior population."""

    collision_id: str
    scope: str
    fold: str
    observed_population_commitment: str

    def __post_init__(self) -> None:
        for name in ("collision_id", "scope", "fold", "observed_population_commitment"):
            _non_empty(name, getattr(self, name))


@dataclass(frozen=True)
class IdentifierPopulationWitness:
    scope: str
    population_basis: str
    population_commitment: str
    population_commitment_fields: tuple[str, ...]
    measurement_predicate: str
    population_count: int
    writer_contract_commitment: str
    measured_at: str
    identifier_policy_digest: str
    identifier_policy_epoch: str
    folds: tuple[FoldMeasurement, ...]
    writer_contract_coverage: float
    writer_policy_mismatch_key_digests: tuple[str, ...]
    historical_key_coverage: float
    historical_history_complete: bool
    historical_collision_records: tuple[HistoricalCollisionRecord, ...]

    @property
    def historical_collision_ids(self) -> tuple[str, ...]:
        return tuple(record.collision_id for record in self.historical_collision_records)

    @property
    def at_cliff_edge(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                measurement.name
                for measurement in self.folds
                if measurement.verdict == "ZERO_AT_SCALE"
                and measurement.headroom_chars == 1
            )
        )


@dataclass(frozen=True)
class IdentifierPopulationValidation:
    measurement_valid_for_use: bool
    must_recompute: bool
    reasons: tuple[str, ...]
    historical_integrity_available: bool
    historical_collision_records: tuple[HistoricalCollisionRecord, ...]
    at_cliff_edge: tuple[str, ...]

    @property
    def historical_collision_ids(self) -> tuple[str, ...]:
        return tuple(record.collision_id for record in self.historical_collision_records)


def _ratio(count: int, total: int) -> float:
    """Return coverage, treating a complete empty population as vacuously covered."""

    return 1.0 if total == 0 else count / total


def issue_identifier_population_witness(
    snapshot: IdentifierPopulationSnapshot,
    folds: Iterable[FoldMeasurement],
    *,
    measured_at: str,
    identifier_policy_digest: str,
    identifier_policy_epoch: str,
    history: HistoricalKeyLedger | None = None,
    historical_collisions: Iterable[HistoricalCollisionRecord] = (),
) -> IdentifierPopulationWitness:
    """Bind identifier measurements to one exact complete population snapshot."""

    if not snapshot.complete:
        raise ValueError("cannot issue an exact witness from an incomplete population snapshot")
    for name, value in (
        ("measured_at", measured_at),
        ("identifier_policy_digest", identifier_policy_digest),
        ("identifier_policy_epoch", identifier_policy_epoch),
    ):
        _non_empty(name, value)

    folds = tuple(folds)
    if len({measurement.name for measurement in folds}) != len(folds):
        raise ValueError("fold measurement names must be unique")

    bound_records = [
        record
        for record in snapshot.records
        if record.writer_policy_digest is not None
        and record.writer_policy_epoch is not None
    ]
    mismatches = tuple(
        sorted(
            record.key_digest
            for record in bound_records
            if record.writer_policy_digest != identifier_policy_digest
            or record.writer_policy_epoch != identifier_policy_epoch
        )
    )

    if history is None:
        historical_key_coverage = 0.0
        historical_history_complete = False
    else:
        if history.scope != snapshot.scope:
            raise ValueError("historical key ledger scope must match snapshot scope")
        historical_set = set(history.key_digests)
        historical_key_coverage = _ratio(
            sum(record.key_digest in historical_set for record in snapshot.records),
            snapshot.population_count,
        )
        historical_history_complete = history.complete

    historical_collisions = tuple(historical_collisions)
    if any(record.scope != snapshot.scope for record in historical_collisions):
        raise ValueError("historical collision scope must match snapshot scope")
    collision_ids = [record.collision_id for record in historical_collisions]
    if len(set(collision_ids)) != len(collision_ids):
        raise ValueError("historical collision ids must be unique")
    retained_collisions = tuple(
        sorted(
            historical_collisions,
            key=lambda record: (
                record.collision_id,
                record.fold,
                record.observed_population_commitment,
            ),
        )
    )

    return IdentifierPopulationWitness(
        scope=snapshot.scope,
        population_basis=snapshot.population_basis,
        population_commitment=snapshot.population_commitment,
        population_commitment_fields=snapshot.population_commitment_fields,
        measurement_predicate=IDENTIFIER_MEASUREMENT_PREDICATE,
        population_count=snapshot.population_count,
        writer_contract_commitment=snapshot.writer_contract_commitment,
        measured_at=measured_at,
        identifier_policy_digest=identifier_policy_digest,
        identifier_policy_epoch=identifier_policy_epoch,
        folds=folds,
        writer_contract_coverage=_ratio(len(bound_records), snapshot.population_count),
        writer_policy_mismatch_key_digests=mismatches,
        historical_key_coverage=historical_key_coverage,
        historical_history_complete=historical_history_complete,
        historical_collision_records=retained_collisions,
    )


def validate_identifier_population_witness(
    witness: IdentifierPopulationWitness,
    current_snapshot: IdentifierPopulationSnapshot,
    *,
    expected_scope: str,
    current_policy_digest: str,
    current_policy_epoch: str,
    expected_population_basis: str = DEFAULT_POPULATION_BASIS,
) -> IdentifierPopulationValidation:
    """Fail closed if a correct measurement no longer describes state at use time.

    Population freshness and historical integrity are deliberately separate.
    A stale population invalidates use of the measurement, while historical
    collision evidence remains visible rather than being erased by deletion.
    """

    for name, value in (
        ("expected_scope", expected_scope),
        ("current_policy_digest", current_policy_digest),
        ("current_policy_epoch", current_policy_epoch),
        ("expected_population_basis", expected_population_basis),
    ):
        _non_empty(name, value)

    reasons: list[str] = []
    foreign_scope = witness.scope != expected_scope or current_snapshot.scope != expected_scope
    if foreign_scope:
        reasons.append("foreign_scope")
    else:
        population_basis_mismatch = (
            witness.population_basis != expected_population_basis
            or current_snapshot.population_basis != expected_population_basis
        )
        if population_basis_mismatch:
            reasons.append("population_basis_mismatch")
        elif not current_snapshot.complete:
            reasons.append("population_incomplete")
        elif current_snapshot.population_commitment != witness.population_commitment:
            reasons.append("population_changed")
        elif current_snapshot.writer_contract_commitment != witness.writer_contract_commitment:
            reasons.append("writer_contract_changed")

    if witness.population_commitment_fields != POPULATION_COMMITMENT_FIELDS:
        reasons.append("commitment_scope_mismatch")
    if witness.measurement_predicate != IDENTIFIER_MEASUREMENT_PREDICATE:
        reasons.append("measurement_predicate_mismatch")

    if (
        witness.identifier_policy_digest != current_policy_digest
        or witness.identifier_policy_epoch != current_policy_epoch
    ):
        reasons.append("identifier_policy_drift")

    if witness.writer_contract_coverage < 1.0:
        reasons.append("writer_policy_unbound")
    if witness.writer_policy_mismatch_key_digests:
        reasons.append("writer_policy_drift")

    reasons = list(dict.fromkeys(reasons))
    historical_integrity_available = (
        witness.historical_history_complete and witness.historical_key_coverage == 1.0
    )

    return IdentifierPopulationValidation(
        measurement_valid_for_use=not reasons,
        must_recompute=bool(reasons),
        reasons=tuple(reasons),
        historical_integrity_available=historical_integrity_available,
        historical_collision_records=witness.historical_collision_records,
        at_cliff_edge=witness.at_cliff_edge,
    )
