"""Fail-closed reviewer persona routing with explicit provider provenance."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

import yaml

_SHA = re.compile(r"^[0-9a-f]{40}$")
_IDENT = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")


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


_RANK = {
    EvidenceLevel.DEGRADED: 1,
    EvidenceLevel.PROXY: 2,
    EvidenceLevel.PROXY_HIGH: 3,
    EvidenceLevel.NATIVE: 4,
}


def _identifier(value: object, label: str) -> str:
    result = str(value).strip().lower()
    if not _IDENT.fullmatch(result):
        raise ReviewerRoutingError(f"invalid {label}: {value!r}")
    return result


def _probability(value: object, label: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ReviewerRoutingError(f"{label} must be a number in [0, 1]") from exc
    if not 0 <= result <= 1:
        raise ReviewerRoutingError(f"{label} must be in [0, 1]")
    return result


def _sha(value: object) -> str:
    result = str(value).strip().lower()
    if not _SHA.fullmatch(result):
        raise ReviewerRoutingError(
            "head_sha must be a full 40-character hexadecimal commit SHA"
        )
    return result


def _status(value: object) -> ProviderStatus:
    try:
        return value if isinstance(value, ProviderStatus) else ProviderStatus(str(value).upper())
    except ValueError as exc:
        raise ReviewerRoutingError(f"unknown provider status: {value!r}") from exc


def _evidence(value: object) -> EvidenceLevel:
    try:
        return value if isinstance(value, EvidenceLevel) else EvidenceLevel(str(value).upper())
    except ValueError as exc:
        raise ReviewerRoutingError(f"unknown evidence level: {value!r}") from exc


@dataclass(frozen=True)
class ReviewerProfile:
    profile_id: str
    version: str
    rubric: tuple[str, ...]
    minimum_compatibility: float = 0.70

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile_id", _identifier(self.profile_id, "profile_id"))
        version = str(self.version).strip()
        if not version or any(ord(char) < 32 for char in version):
            raise ReviewerRoutingError("profile version must be printable text")
        rubric = tuple(str(item).strip() for item in self.rubric)
        if not rubric or any(not item for item in rubric):
            raise ReviewerRoutingError("profile rubric must contain instructions")
        if any(any(ord(char) < 32 for char in item) for item in rubric):
            raise ReviewerRoutingError("profile rubric must be printable text")
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "rubric", rubric)
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
        native = frozenset(_identifier(item, "native profile") for item in self.native_profiles)
        compatibility = {
            _identifier(profile, "compatibility profile"): _probability(score, "compatibility")
            for profile, score in dict(self.compatibility).items()
        }
        compatibility.update({profile: 1.0 for profile in native})
        object.__setattr__(self, "provider_id", provider_id)
        object.__setattr__(self, "status", _status(self.status))
        object.__setattr__(self, "native_profiles", native)
        object.__setattr__(self, "compatibility", dict(sorted(compatibility.items())))
        object.__setattr__(
            self, "historical_quality", _probability(self.historical_quality, "historical_quality")
        )
        object.__setattr__(
            self, "remaining_budget", _probability(self.remaining_budget, "remaining_budget")
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
        object.__setattr__(self, "requested_reviewer", _identifier(self.requested_reviewer, "reviewer"))
        object.__setattr__(self, "profile_id", _identifier(self.profile_id, "profile_id"))
        object.__setattr__(self, "head_sha", _sha(self.head_sha))
        if self.author_engine is not None:
            object.__setattr__(self, "author_engine", _identifier(self.author_engine, "author_engine"))
        object.__setattr__(self, "minimum_evidence", _evidence(self.minimum_evidence))
        if self.max_fallback_hops not in (0, 1):
            raise ReviewerRoutingError("v0.1 supports max_fallback_hops of 0 or 1 only")


@dataclass(frozen=True)
class CandidateAssessment:
    provider_id: str
    status: ProviderStatus
    compatibility: float
    evidence_level: EvidenceLevel
    score: float
    eligible: bool
    rejection_reason: str | None = None

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

    def __post_init__(self) -> None:
        object.__setattr__(self, "requested_reviewer", _identifier(self.requested_reviewer, "reviewer"))
        object.__setattr__(self, "executed_by", _identifier(self.executed_by, "executor"))
        object.__setattr__(self, "profile_id", _identifier(self.profile_id, "profile_id"))
        object.__setattr__(self, "head_sha", _sha(self.head_sha))
        if self.native_review and self.requested_reviewer != self.executed_by:
            raise ReviewerRoutingError("a proxy executor cannot be represented as a native review")
        if self.native_review != (self.evidence_level == EvidenceLevel.NATIVE):
            raise ReviewerRoutingError("NATIVE evidence and native_review must agree")
        if self.fallback_hops not in (0, 1):
            raise ReviewerRoutingError("route supports at most one fallback hop")
        if (self.fallback_hops == 0) != (self.fallback_reason is None):
            raise ReviewerRoutingError("fallback hop and reason must agree")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cml-reviewer-route-v1",
            "requested_reviewer": self.requested_reviewer,
            "executed_by": self.executed_by,
            "profile": {"profile_id": self.profile_id, "version": self.profile_version},
            "head_sha": self.head_sha,
            "native_review": self.native_review,
            "evidence_level": self.evidence_level.value,
            "fallback_reason": self.fallback_reason.value if self.fallback_reason else None,
            "fallback_hops": self.fallback_hops,
            "score": round(self.score, 6),
            "considered": [item.to_dict() for item in self.considered],
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
        code = str(self.code).strip().upper()
        severity = str(self.severity).strip().upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+", code):
            raise ReviewerRoutingError("invalid finding code")
        if severity not in {"P0", "P1", "P2", "P3"}:
            raise ReviewerRoutingError("finding severity must be P0-P3")
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "category", _identifier(self.category, "finding category"))
        object.__setattr__(self, "executed_by", _identifier(self.executed_by, "executor"))
        object.__setattr__(self, "profile_id", _identifier(self.profile_id, "profile_id"))
        object.__setattr__(self, "head_sha", _sha(self.head_sha))
        object.__setattr__(self, "confidence", _probability(self.confidence, "confidence"))
        for name in ("message", "failure_path", "counterexample", "regression_test", "smallest_remediation"):
            value = str(getattr(self, name)).strip()
            if not value:
                raise ReviewerRoutingError(f"finding {name} must be non-empty")
            object.__setattr__(self, name, value)
        if self.path is not None:
            path = str(self.path).strip()
            if not path or path.startswith("/") or ".." in path.split("/"):
                raise ReviewerRoutingError("finding path must be repository-relative")
            object.__setattr__(self, "path", path)

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

    def __init__(self, *, profiles: Sequence[ReviewerProfile], providers: Sequence[ReviewerProvider]):
        self._profiles = self._unique(profiles, lambda item: item.profile_id, "profile")
        self._providers = self._unique(providers, lambda item: item.provider_id, "provider")
        if not self._profiles or not self._providers:
            raise ReviewerRoutingError("profiles and providers must be non-empty")
        unknown = sorted({profile for provider in providers for profile in provider.compatibility if profile not in self._profiles})
        if unknown:
            raise ReviewerRoutingError(f"providers reference unknown profiles: {unknown}")

    @staticmethod
    def _unique(items: Sequence[Any], key, label: str) -> dict[str, Any]:
        result = {}
        for item in items:
            item_id = key(item)
            if item_id in result:
                raise ReviewerRoutingError(f"duplicate reviewer {label}: {item_id}")
            result[item_id] = item
        return dict(sorted(result.items()))

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ReviewerPersonaRouter":
        if not isinstance(raw, Mapping):
            raise ReviewerRoutingError("router config must be a mapping")
        raw_profiles, raw_providers = raw.get("profiles", []), raw.get("providers", [])
        if not isinstance(raw_profiles, list) or not isinstance(raw_providers, list):
            raise ReviewerRoutingError("profiles and providers must be lists")
        profiles = [
            ReviewerProfile(
                profile_id=item.get("profile_id", ""),
                version=item.get("version", ""),
                rubric=tuple(item.get("rubric", ())),
                minimum_compatibility=item.get("minimum_compatibility", 0.70),
            )
            for item in raw_profiles
            if isinstance(item, Mapping)
        ]
        providers = [
            ReviewerProvider(
                provider_id=item.get("provider_id", ""),
                status=item.get("status", ""),
                native_profiles=frozenset(item.get("native_profiles", ())),
                compatibility=dict(item.get("compatibility", {})),
                historical_quality=item.get("historical_quality", 1.0),
                remaining_budget=item.get("remaining_budget", 1.0),
            )
            for item in raw_providers
            if isinstance(item, Mapping)
        ]
        if len(profiles) != len(raw_profiles) or len(providers) != len(raw_providers):
            raise ReviewerRoutingError("every profile and provider must be a mapping")
        return cls(profiles=profiles, providers=providers)

    @classmethod
    def from_yaml_string(cls, text: str) -> "ReviewerPersonaRouter":
        class UniqueKeyLoader(yaml.SafeLoader):
            pass

        def unique_mapping(loader, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if key in result:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping", node.start_mark,
                        f"found duplicate key {key!r}", key_node.start_mark,
                    )
                result[key] = loader.construct_object(value_node, deep=deep)
            return result

        UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
        try:
            return cls.from_dict(yaml.load(text, Loader=UniqueKeyLoader) or {})
        except yaml.YAMLError as exc:
            raise ReviewerRoutingError(f"cannot parse router YAML: {exc}") from exc

    @staticmethod
    def _level(provider: ReviewerProvider, profile: ReviewerProfile, request: ReviewRequest, compatibility: float) -> EvidenceLevel:
        if provider.status != ProviderStatus.AVAILABLE:
            return EvidenceLevel.DEGRADED
        if provider.provider_id == request.requested_reviewer and profile.profile_id in provider.native_profiles:
            return EvidenceLevel.NATIVE
        if compatibility >= 0.85:
            return EvidenceLevel.PROXY_HIGH
        if compatibility >= profile.minimum_compatibility:
            return EvidenceLevel.PROXY
        return EvidenceLevel.DEGRADED

    @staticmethod
    def _score(provider: ReviewerProvider, compatibility: float) -> float:
        availability = 1.0 if provider.status == ProviderStatus.AVAILABLE else 0.60
        return compatibility * provider.historical_quality * max(provider.remaining_budget, 0.05) * availability

    def _assess(self, provider: ReviewerProvider, profile: ReviewerProfile, request: ReviewRequest) -> CandidateAssessment:
        compatibility = provider.compatibility_for(profile.profile_id)
        level = self._level(provider, profile, request, compatibility)
        rejection = None
        if provider.status not in {ProviderStatus.AVAILABLE, ProviderStatus.DEGRADED}:
            rejection = provider.status.value
        elif request.require_independent and provider.provider_id == request.author_engine:
            rejection = FallbackReason.AUTHOR_CONFLICT.value
        elif compatibility < profile.minimum_compatibility:
            rejection = FallbackReason.PROFILE_INCOMPATIBLE.value
        elif _RANK[level] < _RANK[request.minimum_evidence]:
            rejection = f"EVIDENCE_BELOW_MINIMUM:{level.value}<{request.minimum_evidence.value}"
        return CandidateAssessment(
            provider.provider_id, provider.status, compatibility, level,
            self._score(provider, compatibility), rejection is None, rejection,
        )

    @staticmethod
    def _reason(provider: ReviewerProvider, assessment: CandidateAssessment) -> FallbackReason:
        status_reason = {
            ProviderStatus.RATE_LIMITED: FallbackReason.RATE_LIMITED,
            ProviderStatus.UNAVAILABLE: FallbackReason.UNAVAILABLE,
            ProviderStatus.AUTH_FAILED: FallbackReason.AUTH_FAILED,
            ProviderStatus.TIMED_OUT: FallbackReason.TIMED_OUT,
            ProviderStatus.DEGRADED: FallbackReason.DEGRADED,
        }.get(provider.status)
        if status_reason:
            return status_reason
        if assessment.rejection_reason == FallbackReason.AUTHOR_CONFLICT.value:
            return FallbackReason.AUTHOR_CONFLICT
        return FallbackReason.PROFILE_INCOMPATIBLE

    def route(self, request: ReviewRequest) -> RouteDecision:
        profile = self._profiles.get(request.profile_id)
        requested = self._providers.get(request.requested_reviewer)
        if profile is None:
            raise ReviewerRoutingError(f"unknown reviewer profile: {request.profile_id}")
        if requested is None:
            raise ReviewerRoutingError(f"unknown requested reviewer: {request.requested_reviewer}")
        assessments = tuple(self._assess(provider, profile, request) for provider in self._providers.values())
        by_id = {item.provider_id: item for item in assessments}
        selected = by_id[requested.provider_id]
        reason, hops = None, 0
        if not selected.eligible:
            if request.max_fallback_hops == 0:
                raise ReviewerRoutingError("requested reviewer is unavailable and fallback is disabled")
            candidates = [item for item in assessments if item.eligible and item.provider_id != requested.provider_id]
            if not candidates:
                details = {item.provider_id: item.rejection_reason for item in assessments}
                raise ReviewerRoutingError(f"no eligible reviewer provider for exact head {request.head_sha}: {details}")
            selected = sorted(candidates, key=lambda item: (-item.score, -item.compatibility, item.provider_id))[0]
            reason, hops = self._reason(requested, by_id[requested.provider_id]), 1
        native = selected.evidence_level == EvidenceLevel.NATIVE
        return RouteDecision(
            request.requested_reviewer, selected.provider_id, profile.profile_id,
            profile.version, request.head_sha, native, selected.evidence_level,
            reason, hops, selected.score, assessments,
        )

    def render_execution_prompt(self, decision: RouteDecision) -> str:
        profile = self._profiles.get(decision.profile_id)
        if profile is None:
            raise ReviewerRoutingError(f"unknown decision profile: {decision.profile_id}")
        rubric = "\n".join(f"{index}. {item}" for index, item in enumerate(profile.rubric, 1))
        reason = decision.fallback_reason.value if decision.fallback_reason else "NONE"
        kind = "native" if decision.native_review else "proxy"
        return (
            "CML REVIEW EXECUTION CONTRACT\n"
            f"Exact head: {decision.head_sha}\n"
            f"Execution provider: {decision.executed_by}\n"
            f"Requested reviewer: {decision.requested_reviewer}\n"
            f"Persona profile: {decision.profile_id}@{decision.profile_version}\n"
            f"Route kind: {kind}\nEvidence level: {decision.evidence_level.value}\n"
            f"Fallback reason: {reason}\n\n"
            "Identity rule: execute the requested rubric, but never claim to be the requested reviewer unless the execution provider is that same native reviewer. A proxy result is not a native approval and grants no merge authority.\n\n"
            f"Review rubric:\n{rubric}\n\n"
            "For every actionable finding return severity, affected guarantee, exact code boundary, concrete failure path, counterexample, smallest regression test, and minimal remediation. Bind the conclusion to the exact head above."
        )
