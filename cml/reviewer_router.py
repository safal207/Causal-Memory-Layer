"""Fail-closed reviewer persona routing with explicit provider provenance."""
from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

import yaml

_SHA = re.compile(r"^[0-9a-f]{40}$")
_IDENT = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_EVIDENCE_REJECTION = "EVIDENCE_BELOW_MINIMUM:"


class ReviewerRoutingError(ValueError):
    """A safe review route could not be established."""


class ProviderStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    RATE_LIMITED = "RATE_LIMITED"
    UNAVAILABLE = "UNAVAILABLE"
    AUTH_FAILED = "AUTH_FAILED"
    TIMED_OUT = "TIMED_OUT"


class EvidenceLevel(str, Enum):
    DEGRADED = "DEGRADED"
    PROXY = "PROXY"
    PROXY_HIGH = "PROXY_HIGH"
    NATIVE = "NATIVE"


class FallbackReason(str, Enum):
    RATE_LIMITED = "RATE_LIMITED"
    UNAVAILABLE = "UNAVAILABLE"
    AUTH_FAILED = "AUTH_FAILED"
    TIMED_OUT = "TIMED_OUT"
    DEGRADED = "DEGRADED"
    AUTHOR_CONFLICT = "AUTHOR_CONFLICT"
    PROFILE_INCOMPATIBLE = "PROFILE_INCOMPATIBLE"
    EVIDENCE_BELOW_MINIMUM = "EVIDENCE_BELOW_MINIMUM"


_RANK = {
    EvidenceLevel.DEGRADED: 1,
    EvidenceLevel.PROXY: 2,
    EvidenceLevel.PROXY_HIGH: 3,
    EvidenceLevel.NATIVE: 4,
}

_STATUS_FALLBACK = {
    ProviderStatus.RATE_LIMITED: FallbackReason.RATE_LIMITED,
    ProviderStatus.UNAVAILABLE: FallbackReason.UNAVAILABLE,
    ProviderStatus.AUTH_FAILED: FallbackReason.AUTH_FAILED,
    ProviderStatus.TIMED_OUT: FallbackReason.TIMED_OUT,
    ProviderStatus.DEGRADED: FallbackReason.DEGRADED,
}


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ReviewerRoutingError(f"{label} must be text")
    result = value.strip().lower()
    if not _IDENT.fullmatch(result):
        raise ReviewerRoutingError(f"invalid {label}: {value!r}")
    return result


def _probability(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReviewerRoutingError(
            f"{label} must be a number in [0, 1], not {type(value).__name__}"
        )
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= 1:
        raise ReviewerRoutingError(f"{label} must be finite and in [0, 1]")
    return result


def _sha(value: object) -> str:
    if not isinstance(value, str):
        raise ReviewerRoutingError("head_sha must be text")
    result = value.strip().lower()
    if not _SHA.fullmatch(result):
        raise ReviewerRoutingError(
            "head_sha must be a full 40-character hexadecimal commit SHA"
        )
    return result


def _enum(value: object, enum_type: type[Enum], label: str):
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise ReviewerRoutingError(f"{label} must be text")
    try:
        return enum_type(value.upper())
    except ValueError as exc:
        raise ReviewerRoutingError(f"unknown {label}: {value!r}") from exc


def _printable_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ReviewerRoutingError(f"{label} must be text")
    result = value.strip()
    if not result or any(ord(char) < 32 for char in result):
        raise ReviewerRoutingError(f"{label} must be printable text")
    return result


def _string_sequence(value: object, label: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ReviewerRoutingError(f"{label} must be a list")
    result = tuple(_printable_text(item, label) for item in value)
    if not result:
        raise ReviewerRoutingError(f"{label} must not be empty")
    return result


def _identifier_set(value: object, label: str) -> frozenset[str]:
    if isinstance(value, (str, bytes)) or not isinstance(
        value, (Sequence, set, frozenset)
    ):
        raise ReviewerRoutingError(f"{label} must be a list or set")
    normalized: set[str] = set()
    for raw in value:
        item = _identifier(raw, label)
        if item in normalized:
            raise ReviewerRoutingError(f"duplicate normalized {label}: {item}")
        normalized.add(item)
    return frozenset(normalized)


def _compatibility_mapping(value: object) -> Mapping[str, float]:
    if not isinstance(value, Mapping):
        raise ReviewerRoutingError("compatibility must be a mapping")
    normalized: dict[str, float] = {}
    for raw_profile, raw_score in value.items():
        profile = _identifier(raw_profile, "compatibility profile")
        if profile in normalized:
            raise ReviewerRoutingError(
                f"duplicate normalized compatibility profile: {profile}"
            )
        normalized[profile] = _probability(raw_score, "compatibility")
    return MappingProxyType(dict(sorted(normalized.items())))


def _finding_path(value: object) -> str:
    path = _printable_text(value, "finding path")
    if (
        "\\" in path
        or path.startswith("/")
        or path.startswith("//")
        or _WINDOWS_DRIVE.match(path)
    ):
        raise ReviewerRoutingError(
            "finding path must be repository-relative POSIX path"
        )
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ReviewerRoutingError(
            "finding path must be repository-relative POSIX path"
        )
    return path


@dataclass(frozen=True)
class ReviewerProfile:
    profile_id: str
    version: str
    rubric: tuple[str, ...]
    minimum_compatibility: float = 0.70

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "profile_id", _identifier(self.profile_id, "profile_id")
        )
        object.__setattr__(
            self, "version", _printable_text(self.version, "profile version")
        )
        object.__setattr__(
            self, "rubric", _string_sequence(self.rubric, "profile rubric")
        )
        object.__setattr__(
            self,
            "minimum_compatibility",
            _probability(self.minimum_compatibility, "minimum_compatibility"),
        )


@dataclass(frozen=True)
class ReviewerProvider:
    provider_id: str
    status: ProviderStatus
    native_profiles: frozenset[str] = field(default_factory=frozenset)
    compatibility: Mapping[str, float] = field(default_factory=dict)
    historical_quality: float = 1.0
    remaining_budget: float = 1.0

    def __post_init__(self) -> None:
        provider_id = _identifier(self.provider_id, "provider_id")
        native = _identifier_set(self.native_profiles, "native profile")
        compatibility = dict(_compatibility_mapping(self.compatibility))
        for profile in native:
            existing = compatibility.get(profile)
            if existing is not None and existing != 1.0:
                raise ReviewerRoutingError(
                    f"native profile {profile} cannot declare compatibility "
                    f"{existing}; expected 1.0"
                )
            compatibility[profile] = 1.0
        object.__setattr__(self, "provider_id", provider_id)
        object.__setattr__(
            self,
            "status",
            _enum(self.status, ProviderStatus, "provider status"),
        )
        object.__setattr__(self, "native_profiles", native)
        object.__setattr__(
            self,
            "compatibility",
            MappingProxyType(dict(sorted(compatibility.items()))),
        )
        object.__setattr__(
            self,
            "historical_quality",
            _probability(self.historical_quality, "historical_quality"),
        )
        object.__setattr__(
            self,
            "remaining_budget",
            _probability(self.remaining_budget, "remaining_budget"),
        )

    def compatibility_for(self, profile_id: str) -> float:
        return float(self.compatibility.get(profile_id, 0.0))


@dataclass(frozen=True)
class ReviewRequest:
    requested_reviewer: str
    profile_id: str
    head_sha: str
    author_engine: str | None = None
    require_independent: bool = True
    minimum_evidence: EvidenceLevel = EvidenceLevel.PROXY
    max_fallback_hops: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "requested_reviewer",
            _identifier(self.requested_reviewer, "reviewer"),
        )
        object.__setattr__(
            self, "profile_id", _identifier(self.profile_id, "profile_id")
        )
        object.__setattr__(self, "head_sha", _sha(self.head_sha))
        if self.author_engine is not None:
            object.__setattr__(
                self,
                "author_engine",
                _identifier(self.author_engine, "author_engine"),
            )
        if not isinstance(self.require_independent, bool):
            raise ReviewerRoutingError("require_independent must be boolean")
        object.__setattr__(
            self,
            "minimum_evidence",
            _enum(self.minimum_evidence, EvidenceLevel, "evidence level"),
        )
        if isinstance(self.max_fallback_hops, bool) or self.max_fallback_hops not in (
            0,
            1,
        ):
            raise ReviewerRoutingError(
                "v0.1 supports max_fallback_hops of 0 or 1 only"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_reviewer": self.requested_reviewer,
            "profile_id": self.profile_id,
            "head_sha": self.head_sha,
            "author_engine": self.author_engine,
            "require_independent": self.require_independent,
            "minimum_evidence": self.minimum_evidence.value,
            "max_fallback_hops": self.max_fallback_hops,
        }


@dataclass(frozen=True)
class CandidateAssessment:
    provider_id: str
    status: ProviderStatus
    compatibility: float
    evidence_level: EvidenceLevel
    score: float
    eligible: bool
    rejection_reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "provider_id", _identifier(self.provider_id, "provider_id")
        )
        object.__setattr__(
            self,
            "status",
            _enum(self.status, ProviderStatus, "provider status"),
        )
        object.__setattr__(
            self,
            "compatibility",
            _probability(self.compatibility, "compatibility"),
        )
        object.__setattr__(
            self,
            "evidence_level",
            _enum(self.evidence_level, EvidenceLevel, "evidence level"),
        )
        object.__setattr__(
            self, "score", _probability(self.score, "candidate score")
        )
        if not isinstance(self.eligible, bool):
            raise ReviewerRoutingError("candidate eligible must be boolean")
        if self.rejection_reason is not None:
            object.__setattr__(
                self,
                "rejection_reason",
                _printable_text(self.rejection_reason, "rejection reason"),
            )
        if self.eligible != (self.rejection_reason is None):
            raise ReviewerRoutingError(
                "candidate eligibility and rejection reason must agree"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "status": self.status.value,
            "compatibility": round(self.compatibility, 6),
            "evidence_level": self.evidence_level.value,
            "score": round(self.score, 6),
            "eligible": self.eligible,
            "rejection_reason": self.rejection_reason,
        }


@dataclass(frozen=True)
class RouteDecision:
    requested_reviewer: str
    executed_by: str
    profile_id: str
    profile_version: str
    head_sha: str
    native_review: bool
    evidence_level: EvidenceLevel
    fallback_reason: FallbackReason | None
    fallback_hops: int
    score: float
    considered: tuple[CandidateAssessment, ...]
    request: ReviewRequest | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "requested_reviewer",
            _identifier(self.requested_reviewer, "reviewer"),
        )
        object.__setattr__(
            self, "executed_by", _identifier(self.executed_by, "executor")
        )
        object.__setattr__(
            self, "profile_id", _identifier(self.profile_id, "profile_id")
        )
        object.__setattr__(
            self,
            "profile_version",
            _printable_text(self.profile_version, "profile version"),
        )
        object.__setattr__(self, "head_sha", _sha(self.head_sha))
        if not isinstance(self.native_review, bool):
            raise ReviewerRoutingError("native_review must be boolean")
        object.__setattr__(
            self,
            "evidence_level",
            _enum(self.evidence_level, EvidenceLevel, "evidence level"),
        )
        if self.fallback_reason is not None:
            object.__setattr__(
                self,
                "fallback_reason",
                _enum(self.fallback_reason, FallbackReason, "fallback reason"),
            )
        if isinstance(self.fallback_hops, bool) or self.fallback_hops not in (0, 1):
            raise ReviewerRoutingError("route supports at most one fallback hop")
        object.__setattr__(
            self, "score", _probability(self.score, "route score")
        )
        if self.native_review and self.requested_reviewer != self.executed_by:
            raise ReviewerRoutingError(
                "a proxy executor cannot be represented as a native review"
            )
        if self.native_review != (self.evidence_level == EvidenceLevel.NATIVE):
            raise ReviewerRoutingError(
                "NATIVE evidence and native_review must agree"
            )
        if isinstance(self.considered, (str, bytes)) or not isinstance(
            self.considered, Sequence
        ):
            raise ReviewerRoutingError(
                "considered must be a sequence of assessments"
            )
        considered = tuple(self.considered)
        if not considered or any(
            not isinstance(item, CandidateAssessment) for item in considered
        ):
            raise ReviewerRoutingError(
                "considered must contain candidate assessments"
            )
        provider_ids = [item.provider_id for item in considered]
        if len(provider_ids) != len(set(provider_ids)):
            raise ReviewerRoutingError("considered contains duplicate providers")
        object.__setattr__(self, "considered", considered)
        if self.request is not None and not isinstance(self.request, ReviewRequest):
            raise ReviewerRoutingError(
                "request provenance must be a ReviewRequest"
            )
        if (self.fallback_hops == 0) != (self.fallback_reason is None):
            raise ReviewerRoutingError("fallback hop and reason must agree")
        if self.fallback_hops == 0 and self.executed_by != self.requested_reviewer:
            raise ReviewerRoutingError(
                "zero-hop route must execute on the requested reviewer"
            )
        if self.fallback_hops == 1 and self.executed_by == self.requested_reviewer:
            raise ReviewerRoutingError(
                "fallback route must change execution provider"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cml-reviewer-route-v1",
            "requested_reviewer": self.requested_reviewer,
            "executed_by": self.executed_by,
            "profile": {
                "profile_id": self.profile_id,
                "version": self.profile_version,
            },
            "head_sha": self.head_sha,
            "native_review": self.native_review,
            "evidence_level": self.evidence_level.value,
            "fallback_reason": (
                self.fallback_reason.value if self.fallback_reason else None
            ),
            "fallback_hops": self.fallback_hops,
            "score": round(self.score, 6),
            "considered": [item.to_dict() for item in self.considered],
            "request": self.request.to_dict() if self.request else None,
            "merge_authority": False,
        }


@dataclass(frozen=True)
class NormalizedReviewFinding:
    code: str
    severity: str
    category: str
    message: str
    failure_path: str
    counterexample: str
    regression_test: str
    smallest_remediation: str
    confidence: float
    executed_by: str
    profile_id: str
    head_sha: str
    path: str | None = None

    def __post_init__(self) -> None:
        code = _printable_text(self.code, "finding code").upper()
        severity = _printable_text(self.severity, "finding severity").upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+", code):
            raise ReviewerRoutingError("invalid finding code")
        if severity not in {"P0", "P1", "P2", "P3"}:
            raise ReviewerRoutingError("finding severity must be P0-P3")
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(
            self, "category", _identifier(self.category, "finding category")
        )
        object.__setattr__(
            self, "executed_by", _identifier(self.executed_by, "executor")
        )
        object.__setattr__(
            self, "profile_id", _identifier(self.profile_id, "profile_id")
        )
        object.__setattr__(self, "head_sha", _sha(self.head_sha))
        object.__setattr__(
            self, "confidence", _probability(self.confidence, "confidence")
        )
        for name in (
            "message",
            "failure_path",
            "counterexample",
            "regression_test",
            "smallest_remediation",
        ):
            object.__setattr__(
                self,
                name,
                _printable_text(getattr(self, name), f"finding {name}"),
            )
        if self.path is not None:
            object.__setattr__(self, "path", _finding_path(self.path))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cml-normalized-review-finding-v1",
            "code": self.code,
            "severity": self.severity,
            "category": self.category,
            "path": self.path,
            "message": self.message,
            "failure_path": self.failure_path,
            "counterexample": self.counterexample,
            "regression_test": self.regression_test,
            "smallest_remediation": self.smallest_remediation,
            "confidence": self.confidence,
            "executed_by": self.executed_by,
            "profile_id": self.profile_id,
            "head_sha": self.head_sha,
        }


class ReviewerPersonaRouter:
    """Choose an executor while preserving the requested persona and provenance."""

    def __init__(
        self,
        *,
        profiles: Sequence[ReviewerProfile],
        providers: Sequence[ReviewerProvider],
    ) -> None:
        self._profiles = self._unique(
            profiles, lambda item: item.profile_id, "profile"
        )
        self._providers = self._unique(
            providers, lambda item: item.provider_id, "provider"
        )
        if not self._profiles or not self._providers:
            raise ReviewerRoutingError("profiles and providers must be non-empty")
        unknown = sorted(
            {
                profile
                for provider in providers
                for profile in provider.compatibility
                if profile not in self._profiles
            }
        )
        if unknown:
            raise ReviewerRoutingError(
                f"providers reference unknown profiles: {unknown}"
            )

    @staticmethod
    def _unique(items: Sequence[Any], key, label: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for item in items:
            item_id = key(item)
            if item_id in result:
                raise ReviewerRoutingError(
                    f"duplicate reviewer {label}: {item_id}"
                )
            result[item_id] = item
        return dict(sorted(result.items()))

    @staticmethod
    def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise ReviewerRoutingError(f"{label} must be a mapping")
        return value

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ReviewerPersonaRouter":
        if not isinstance(raw, Mapping):
            raise ReviewerRoutingError("router config must be a mapping")
        raw_profiles = raw.get("profiles", [])
        raw_providers = raw.get("providers", [])
        if not isinstance(raw_profiles, list) or not isinstance(
            raw_providers, list
        ):
            raise ReviewerRoutingError("profiles and providers must be lists")
        profiles: list[ReviewerProfile] = []
        for raw_profile in raw_profiles:
            item = cls._require_mapping(raw_profile, "profile")
            profiles.append(
                ReviewerProfile(
                    profile_id=item.get("profile_id", ""),
                    version=item.get("version", ""),
                    rubric=_string_sequence(
                        item.get("rubric", ()), "profile rubric"
                    ),
                    minimum_compatibility=item.get(
                        "minimum_compatibility", 0.70
                    ),
                )
            )
        providers: list[ReviewerProvider] = []
        for raw_provider in raw_providers:
            item = cls._require_mapping(raw_provider, "provider")
            providers.append(
                ReviewerProvider(
                    provider_id=item.get("provider_id", ""),
                    status=item.get("status", ""),
                    native_profiles=_identifier_set(
                        item.get("native_profiles", ()), "native profile"
                    ),
                    compatibility=_compatibility_mapping(
                        item.get("compatibility", {})
                    ),
                    historical_quality=item.get("historical_quality", 1.0),
                    remaining_budget=item.get("remaining_budget", 1.0),
                )
            )
        return cls(profiles=profiles, providers=providers)

    @classmethod
    def from_yaml_string(cls, text: str) -> "ReviewerPersonaRouter":
        if not isinstance(text, str):
            raise ReviewerRoutingError("router YAML must be text")

        class UniqueKeyLoader(yaml.SafeLoader):
            pass

        def unique_mapping(loader, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if not isinstance(key, str):
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        f"mapping key must be text, got {type(key).__name__}",
                        key_node.start_mark,
                    )
                if key in result:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        f"found duplicate key {key!r}",
                        key_node.start_mark,
                    )
                result[key] = loader.construct_object(value_node, deep=deep)
            return result

        UniqueKeyLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
            unique_mapping,
        )
        try:
            payload = yaml.load(text, Loader=UniqueKeyLoader) or {}
            return cls.from_dict(payload)
        except ReviewerRoutingError:
            raise
        except (yaml.YAMLError, TypeError, ValueError) as exc:
            raise ReviewerRoutingError(
                f"cannot parse router YAML: {exc}"
            ) from exc

    @staticmethod
    def _level(
        provider: ReviewerProvider,
        profile: ReviewerProfile,
        request: ReviewRequest,
        compatibility: float,
    ) -> EvidenceLevel:
        if provider.status != ProviderStatus.AVAILABLE:
            return EvidenceLevel.DEGRADED
        if (
            provider.provider_id == request.requested_reviewer
            and profile.profile_id in provider.native_profiles
        ):
            return EvidenceLevel.NATIVE
        if compatibility >= 0.85:
            return EvidenceLevel.PROXY_HIGH
        if compatibility >= profile.minimum_compatibility:
            return EvidenceLevel.PROXY
        return EvidenceLevel.DEGRADED

    @staticmethod
    def _score(provider: ReviewerProvider, compatibility: float) -> float:
        availability = (
            1.0 if provider.status == ProviderStatus.AVAILABLE else 0.60
        )
        return (
            compatibility
            * provider.historical_quality
            * max(provider.remaining_budget, 0.05)
            * availability
        )

    def _assess(
        self,
        provider: ReviewerProvider,
        profile: ReviewerProfile,
        request: ReviewRequest,
    ) -> CandidateAssessment:
        compatibility = provider.compatibility_for(profile.profile_id)
        level = self._level(provider, profile, request, compatibility)
        rejection: str | None = None
        if (
            request.require_independent
            and provider.provider_id == request.author_engine
        ):
            rejection = FallbackReason.AUTHOR_CONFLICT.value
        elif compatibility < profile.minimum_compatibility:
            rejection = FallbackReason.PROFILE_INCOMPATIBLE.value
        elif provider.status == ProviderStatus.DEGRADED:
            if request.minimum_evidence != EvidenceLevel.DEGRADED:
                rejection = FallbackReason.DEGRADED.value
        elif provider.status != ProviderStatus.AVAILABLE:
            rejection = provider.status.value
        elif _RANK[level] < _RANK[request.minimum_evidence]:
            rejection = (
                f"{_EVIDENCE_REJECTION}{level.value}"
                f"<{request.minimum_evidence.value}"
            )
        return CandidateAssessment(
            provider_id=provider.provider_id,
            status=provider.status,
            compatibility=compatibility,
            evidence_level=level,
            score=self._score(provider, compatibility),
            eligible=rejection is None,
            rejection_reason=rejection,
        )

    @staticmethod
    def _reason(
        provider: ReviewerProvider,
        assessment: CandidateAssessment,
    ) -> FallbackReason:
        explicit = assessment.rejection_reason
        if explicit == FallbackReason.AUTHOR_CONFLICT.value:
            return FallbackReason.AUTHOR_CONFLICT
        if explicit == FallbackReason.PROFILE_INCOMPATIBLE.value:
            return FallbackReason.PROFILE_INCOMPATIBLE
        if explicit and explicit.startswith(_EVIDENCE_REJECTION):
            return FallbackReason.EVIDENCE_BELOW_MINIMUM
        if explicit:
            for status, fallback in _STATUS_FALLBACK.items():
                if explicit == status.value:
                    return fallback
            raise ReviewerRoutingError(f"unknown rejection cause: {explicit}")
        status_reason = _STATUS_FALLBACK.get(provider.status)
        if status_reason is not None:
            return status_reason
        raise ReviewerRoutingError(
            "ineligible reviewer has no fallback cause"
        )

    def route(self, request: ReviewRequest) -> RouteDecision:
        profile = self._profiles.get(request.profile_id)
        requested = self._providers.get(request.requested_reviewer)
        if profile is None:
            raise ReviewerRoutingError(
                f"unknown reviewer profile: {request.profile_id}"
            )
        if requested is None:
            raise ReviewerRoutingError(
                f"unknown requested reviewer: {request.requested_reviewer}"
            )
        assessments = tuple(
            self._assess(provider, profile, request)
            for provider in self._providers.values()
        )
        by_id = {item.provider_id: item for item in assessments}
        selected = by_id[requested.provider_id]
        reason: FallbackReason | None = None
        hops = 0
        if not selected.eligible:
            if request.max_fallback_hops == 0:
                raise ReviewerRoutingError(
                    "requested reviewer is unavailable and fallback is disabled"
                )
            candidates = [
                item
                for item in assessments
                if item.eligible and item.provider_id != requested.provider_id
            ]
            if not candidates:
                details = {
                    item.provider_id: item.rejection_reason
                    for item in assessments
                }
                raise ReviewerRoutingError(
                    f"no eligible reviewer provider for exact head "
                    f"{request.head_sha}: {details}"
                )
            selected = sorted(
                candidates,
                key=lambda item: (
                    -item.score,
                    -item.compatibility,
                    item.provider_id,
                ),
            )[0]
            reason = self._reason(requested, by_id[requested.provider_id])
            hops = 1
        native = selected.evidence_level == EvidenceLevel.NATIVE
        return RouteDecision(
            requested_reviewer=request.requested_reviewer,
            executed_by=selected.provider_id,
            profile_id=profile.profile_id,
            profile_version=profile.version,
            head_sha=request.head_sha,
            native_review=native,
            evidence_level=selected.evidence_level,
            fallback_reason=reason,
            fallback_hops=hops,
            score=selected.score,
            considered=assessments,
            request=request,
        )

    @staticmethod
    def _decision_claim_signature(decision: RouteDecision) -> tuple[Any, ...]:
        """Return externally asserted claims; scores and assessments are derived."""
        return (
            decision.requested_reviewer,
            decision.executed_by,
            decision.profile_id,
            decision.profile_version,
            decision.head_sha,
            decision.native_review,
            decision.evidence_level,
            decision.fallback_reason,
            decision.fallback_hops,
        )

    def validate_decision(self, decision: RouteDecision) -> RouteDecision:
        if not isinstance(decision, RouteDecision):
            raise ReviewerRoutingError("decision must be a RouteDecision")
        if decision.request is None:
            raise ReviewerRoutingError("decision lacks request provenance")
        request = decision.request
        if (
            request.requested_reviewer != decision.requested_reviewer
            or request.profile_id != decision.profile_id
            or request.head_sha != decision.head_sha
        ):
            raise ReviewerRoutingError(
                "decision fields do not match request provenance"
            )
        expected = self.route(request)
        if self._decision_claim_signature(
            decision
        ) != self._decision_claim_signature(expected):
            raise ReviewerRoutingError(
                "decision claims do not match the route recomputed from "
                "router configuration"
            )
        return expected

    def render_execution_prompt(self, decision: RouteDecision) -> str:
        decision = self.validate_decision(decision)
        profile = self._profiles[decision.profile_id]
        rubric = "\n".join(
            f"{index}. {item}"
            for index, item in enumerate(profile.rubric, 1)
        )
        reason = (
            decision.fallback_reason.value
            if decision.fallback_reason
            else "NONE"
        )
        if decision.evidence_level == EvidenceLevel.NATIVE:
            kind = "native"
        elif (
            decision.evidence_level == EvidenceLevel.DEGRADED
            and decision.fallback_hops == 0
        ):
            kind = "degraded"
        else:
            kind = "proxy"
        return (
            "CML REVIEW EXECUTION CONTRACT\n"
            f"Exact head: {decision.head_sha}\n"
            f"Execution provider: {decision.executed_by}\n"
            f"Requested reviewer: {decision.requested_reviewer}\n"
            f"Persona profile: {decision.profile_id}@{decision.profile_version}\n"
            f"Route kind: {kind}\n"
            f"Evidence level: {decision.evidence_level.value}\n"
            f"Fallback reason: {reason}\n\n"
            "Identity rule: execute the requested rubric, but never claim to be "
            "the requested reviewer unless the execution provider is that same "
            "native reviewer. A proxy result is not a native approval and grants "
            "no merge authority.\n\n"
            f"Review rubric:\n{rubric}\n\n"
            "For every actionable finding return severity, affected guarantee, "
            "exact code boundary, concrete failure path, counterexample, smallest "
            "regression test, and minimal remediation. Bind the conclusion to the "
            "exact head above."
        )
