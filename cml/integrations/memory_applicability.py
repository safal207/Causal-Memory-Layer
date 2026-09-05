"""Deterministic current-state applicability checks for historical memory.

Historical evidence and current authority are intentionally separate. A memory
may remain valid evidence of a past decision while requiring revalidation before
it can influence an action in a changed environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import re
from typing import Mapping

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$")

RESERVED_METADATA_KEYS = frozenset(
    {
        "applicability_verdict",
        "environment_verified",
        "provenance_verified",
        "source_verified",
        "warrant",
    }
)
RESERVED_METADATA_PREFIX = "_cml_"
ENVIRONMENT_FIELDS = (
    "repository",
    "branch",
    "commit_sha",
    "workspace",
    "actor",
    "tenant",
    "policy_digest",
    "target_state_digest",
    "api_version",
    "model_version",
)
REQUIRED_CURRENT_BINDINGS = ("repository", "commit_sha")
LINEAGE_STATES = frozenset({"active", "superseded", "retired", "erased"})


class ApplicabilityStatus(str, Enum):
    """Deterministic result of source and current-environment checks."""

    MATCH = "MATCH"
    DRIFT = "DRIFT"
    ORPHAN = "ORPHAN"
    UNRESOLVABLE = "UNRESOLVABLE"
    REJECT = "REJECT"
    REVALIDATE = "REVALIDATE"


@dataclass(frozen=True)
class SourceObservation:
    """Trusted adapter observation of the authoritative source.

    ``refetchable`` is explicit because a populated ``source`` string is not
    equivalent to an origin that can be revisited. For example, ``agent:writer``
    identifies a writer but does not by itself identify re-fetchable content.
    """

    locator: str | None
    refetchable: bool
    exists: bool | None
    expected_digest: str | None = None
    observed_digest: str | None = None

    def __post_init__(self) -> None:
        if self.locator is not None and not self.locator.strip():
            raise ValueError("locator must be non-empty when provided")
        if not isinstance(self.refetchable, bool):
            raise TypeError("refetchable must be boolean")
        if self.exists is not None and not isinstance(self.exists, bool):
            raise TypeError("exists must be boolean or None")
        for label, value in (
            ("expected_digest", self.expected_digest),
            ("observed_digest", self.observed_digest),
        ):
            if value is not None and not SHA256_HEX.fullmatch(value):
                raise ValueError(f"{label} must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class LineageDependency:
    """Current observation of one dependency used to derive a memory.

    Lineage is intentionally distinct from the derived record's own source.
    A summary can still match its own source while one of the records it was
    derived from has been superseded, retired, erased, or changed.
    """

    dependency_id: str
    state: str
    expected_digest: str | None = None
    observed_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.dependency_id, str) or not self.dependency_id.strip():
            raise ValueError("dependency_id must be a non-empty string")
        if self.state not in LINEAGE_STATES:
            raise ValueError(
                "state must be one of: active, superseded, retired, erased"
            )
        for label, value in (
            ("expected_digest", self.expected_digest),
            ("observed_digest", self.observed_digest),
        ):
            if value is not None and not SHA256_HEX.fullmatch(value):
                raise ValueError(f"{label} must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class EnvironmentBinding:
    """Environment facts a memory was validated against.

    A ``None`` value normally means that dimension was not bound historically.
    Repository and commit SHA are stricter: if current authoritative state
    provides either dimension, historical evidence must have bound it before an
    exact ``MATCH`` is possible.
    """

    repository: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    workspace: str | None = None
    actor: str | None = None
    tenant: str | None = None
    policy_digest: str | None = None
    target_state_digest: str | None = None
    api_version: str | None = None
    model_version: str | None = None
    observed_at: str | None = None
    valid_until: str | None = None

    def __post_init__(self) -> None:
        for name in ENVIRONMENT_FIELDS:
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be a non-empty string when provided")
        if self.commit_sha is not None and not GIT_SHA.fullmatch(self.commit_sha):
            raise ValueError("commit_sha must be a lowercase 40-character Git SHA")
        for name in ("policy_digest", "target_state_digest"):
            value = getattr(self, name)
            if value is not None and not SHA256_HEX.fullmatch(value):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        observed = _parse_timestamp(self.observed_at, label="observed_at")
        valid_until = _parse_timestamp(self.valid_until, label="valid_until")
        if observed is not None and valid_until is not None and valid_until <= observed:
            raise ValueError("valid_until must be later than observed_at")


@dataclass(frozen=True)
class ApplicabilityResult:
    status: ApplicabilityStatus
    reasons: tuple[str, ...]

    @property
    def may_influence_action(self) -> bool:
        """Only an exact current-state match may proceed without revalidation."""

        return self.status is ApplicabilityStatus.MATCH


def _parse_timestamp(value: str | None, *, label: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or not RFC3339_UTC.fullmatch(value):
        raise ValueError(f"{label} must be RFC3339 UTC with optional milliseconds")
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ" if "." in value else "%Y-%m-%dT%H:%M:%SZ"
    try:
        return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid RFC3339 UTC timestamp") from exc


def _validate_now(now: datetime) -> datetime:
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")
    return now.astimezone(timezone.utc)


def forged_reserved_metadata(metadata: Mapping[str, object] | None) -> tuple[str, ...]:
    """Return caller-supplied keys that collide with the internal trust namespace."""

    if metadata is None:
        return ()
    forged: list[str] = []
    for key in metadata:
        if not isinstance(key, str):
            forged.append(repr(key))
            continue
        if key in RESERVED_METADATA_KEYS or key.startswith(RESERVED_METADATA_PREFIX):
            forged.append(key)
    return tuple(sorted(forged))


def missing_historical_required_bindings(
    stored: EnvironmentBinding,
    current: EnvironmentBinding,
) -> tuple[str, ...]:
    """Return current immutable bindings absent from historical evidence."""

    missing = [
        f"environment_unbound:{name}"
        for name in REQUIRED_CURRENT_BINDINGS
        if getattr(current, name) is not None and getattr(stored, name) is None
    ]
    return tuple(sorted(missing))


def lineage_revalidation_reasons(
    lineage: tuple[LineageDependency, ...],
) -> tuple[str, ...]:
    """Return deterministic reasons a derived memory must be revalidated.

    The check is local to the memory store: it does not require re-fetching the
    derived record's external source. This lets supersession and erasure remain
    detectable even when source refetch coverage is low.
    """

    reasons: list[str] = []
    seen: set[str] = set()

    for dependency in lineage:
        if dependency.dependency_id in seen:
            reasons.append(f"lineage_duplicate:{dependency.dependency_id}")
            continue
        seen.add(dependency.dependency_id)

        if dependency.state != "active":
            reasons.append(
                f"lineage_invalidated:{dependency.dependency_id}:{dependency.state}"
            )
            continue

        if dependency.expected_digest is None or dependency.observed_digest is None:
            reasons.append(f"lineage_unverifiable:{dependency.dependency_id}")
            continue

        if dependency.expected_digest != dependency.observed_digest:
            reasons.append(f"lineage_changed:{dependency.dependency_id}")

    return tuple(sorted(reasons))


def environment_mismatches(
    stored: EnvironmentBinding,
    current: EnvironmentBinding,
    *,
    now: datetime,
) -> tuple[str, ...]:
    """Return deterministic reasons why historical environment is not current."""

    reasons: list[str] = []
    for name in ENVIRONMENT_FIELDS:
        expected = getattr(stored, name)
        if expected is None:
            continue
        observed = getattr(current, name)
        if observed != expected:
            reasons.append(f"environment_mismatch:{name}")

    valid_until = _parse_timestamp(stored.valid_until, label="valid_until")
    if valid_until is not None and _validate_now(now) >= valid_until:
        reasons.append("environment_expired:valid_until")

    return tuple(sorted(reasons))


def evaluate_memory_applicability(
    *,
    source: SourceObservation,
    stored_environment: EnvironmentBinding,
    current_environment: EnvironmentBinding,
    now: datetime,
    caller_metadata: Mapping[str, object] | None = None,
    lineage: tuple[LineageDependency, ...] = (),
) -> ApplicabilityResult:
    """Evaluate source integrity, lineage, and current-state applicability.

    Precedence is deliberately fail-closed:

    REJECT -> UNRESOLVABLE -> ORPHAN -> DRIFT -> REVALIDATE -> MATCH.

    Within ``REVALIDATE``, lineage/supersession is checked before environment
    drift. Source I/O is adapter-owned. This pure function consumes trusted
    observations so the verdict itself is deterministic and fixture-friendly.
    """

    forged = forged_reserved_metadata(caller_metadata)
    if forged:
        return ApplicabilityResult(
            ApplicabilityStatus.REJECT,
            tuple(f"reserved_metadata:{key}" for key in forged),
        )

    if source.locator is None or not source.refetchable:
        return ApplicabilityResult(
            ApplicabilityStatus.UNRESOLVABLE,
            ("source_not_refetchable",),
        )

    if source.exists is False:
        return ApplicabilityResult(
            ApplicabilityStatus.ORPHAN,
            ("source_missing",),
        )
    if source.exists is None:
        return ApplicabilityResult(
            ApplicabilityStatus.UNRESOLVABLE,
            ("source_existence_unknown",),
        )

    if source.expected_digest is None or source.observed_digest is None:
        return ApplicabilityResult(
            ApplicabilityStatus.UNRESOLVABLE,
            ("source_digest_unverifiable",),
        )
    if source.expected_digest != source.observed_digest:
        return ApplicabilityResult(
            ApplicabilityStatus.DRIFT,
            ("source_digest_mismatch",),
        )

    lineage_reasons = lineage_revalidation_reasons(lineage)
    missing_bindings = missing_historical_required_bindings(
        stored_environment,
        current_environment,
    )
    mismatches = environment_mismatches(
        stored_environment,
        current_environment,
        now=now,
    )
    revalidation_reasons = tuple(
        sorted((*lineage_reasons, *missing_bindings, *mismatches))
    )
    if revalidation_reasons:
        return ApplicabilityResult(
            ApplicabilityStatus.REVALIDATE,
            revalidation_reasons,
        )

    return ApplicabilityResult(ApplicabilityStatus.MATCH, ())
