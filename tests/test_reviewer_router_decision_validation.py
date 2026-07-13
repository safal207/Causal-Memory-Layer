from __future__ import annotations

from dataclasses import replace

import pytest

from cml.reviewer_router import (
    CandidateAssessment,
    EvidenceLevel,
    FallbackReason,
    NormalizedReviewFinding,
    ProviderStatus,
    ReviewRequest,
    ReviewerPersonaRouter,
    ReviewerProfile,
    ReviewerProvider,
    ReviewerRoutingError,
    RouteDecision,
)

SHA = "c" * 40


def profile() -> ReviewerProfile:
    return ReviewerProfile(
        profile_id="coderabbit-style",
        version="1",
        rubric=("Review the complete diff.",),
        minimum_compatibility=0.70,
    )


def finding(path: str) -> NormalizedReviewFinding:
    return NormalizedReviewFinding(
        code="CML-PATH-VALIDATION",
        severity="P2",
        category="correctness",
        path=path,
        message="Finding path must remain inside the repository.",
        failure_path="A consumer resolves an unsafe path.",
        counterexample=path,
        regression_test="Construct a finding with the unsafe path.",
        smallest_remediation="Require repository-relative POSIX paths.",
        confidence=0.95,
        executed_by="qodo",
        profile_id="coderabbit-style",
        head_sha=SHA,
    )


def test_render_recomputes_route_and_rejects_forged_native_claim():
    router = ReviewerPersonaRouter(
        profiles=[profile()],
        providers=[
            ReviewerProvider(
                provider_id="coderabbit",
                status=ProviderStatus.AVAILABLE,
                compatibility={"coderabbit-style": 0.90},
            )
        ],
    )
    request = ReviewRequest(
        requested_reviewer="coderabbit",
        profile_id="coderabbit-style",
        head_sha=SHA,
    )
    valid = router.route(request)
    assert valid.evidence_level == EvidenceLevel.PROXY_HIGH

    forged = replace(
        valid,
        native_review=True,
        evidence_level=EvidenceLevel.NATIVE,
    )

    with pytest.raises(ReviewerRoutingError, match="recomputed"):
        router.render_execution_prompt(forged)


def test_render_rejects_decision_without_request_provenance():
    assessment = CandidateAssessment(
        provider_id="coderabbit",
        status=ProviderStatus.AVAILABLE,
        compatibility=1.0,
        evidence_level=EvidenceLevel.NATIVE,
        score=1.0,
        eligible=True,
    )
    decision = RouteDecision(
        requested_reviewer="coderabbit",
        executed_by="coderabbit",
        profile_id="coderabbit-style",
        profile_version="1",
        head_sha=SHA,
        native_review=True,
        evidence_level=EvidenceLevel.NATIVE,
        fallback_reason=None,
        fallback_hops=0,
        score=1.0,
        considered=[assessment],
    )
    assert decision.considered == (assessment,)

    router = ReviewerPersonaRouter(
        profiles=[profile()],
        providers=[
            ReviewerProvider(
                provider_id="coderabbit",
                status=ProviderStatus.AVAILABLE,
                native_profiles=frozenset({"coderabbit-style"}),
            )
        ],
    )
    with pytest.raises(ReviewerRoutingError, match="request provenance"):
        router.render_execution_prompt(decision)


def test_tampered_derived_evidence_is_replaced_by_canonical_route():
    router = ReviewerPersonaRouter(
        profiles=[profile()],
        providers=[
            ReviewerProvider(
                provider_id="coderabbit",
                status=ProviderStatus.RATE_LIMITED,
                native_profiles=frozenset({"coderabbit-style"}),
            ),
            ReviewerProvider(
                provider_id="qodo",
                status=ProviderStatus.AVAILABLE,
                compatibility={"coderabbit-style": 0.90},
            ),
        ],
    )
    valid = router.route(
        ReviewRequest(
            requested_reviewer="coderabbit",
            profile_id="coderabbit-style",
            head_sha=SHA,
        )
    )
    tampered_qodo = replace(valid.considered[1], score=0.10)
    tampered = replace(
        valid,
        score=0.10,
        considered=[valid.considered[0], tampered_qodo],
    )

    canonical = router.validate_decision(tampered)
    assert canonical == valid
    assert router.render_execution_prompt(tampered) == router.render_execution_prompt(
        valid
    )


def test_rounded_serialized_derived_evidence_can_be_rehydrated():
    router = ReviewerPersonaRouter(
        profiles=[profile()],
        providers=[
            ReviewerProvider(
                provider_id="coderabbit",
                status=ProviderStatus.RATE_LIMITED,
                native_profiles=frozenset({"coderabbit-style"}),
            ),
            ReviewerProvider(
                provider_id="qodo",
                status=ProviderStatus.AVAILABLE,
                compatibility={"coderabbit-style": 0.913579},
                historical_quality=0.876543,
                remaining_budget=0.765432,
            ),
        ],
    )
    valid = router.route(
        ReviewRequest(
            requested_reviewer="coderabbit",
            profile_id="coderabbit-style",
            head_sha=SHA,
        )
    )
    payload = valid.to_dict()
    reconstructed = RouteDecision(
        requested_reviewer=payload["requested_reviewer"],
        executed_by=payload["executed_by"],
        profile_id=payload["profile"]["profile_id"],
        profile_version=payload["profile"]["version"],
        head_sha=payload["head_sha"],
        native_review=payload["native_review"],
        evidence_level=payload["evidence_level"],
        fallback_reason=payload["fallback_reason"],
        fallback_hops=payload["fallback_hops"],
        score=payload["score"],
        considered=[
            CandidateAssessment(
                provider_id=item["provider_id"],
                status=item["status"],
                compatibility=item["compatibility"],
                evidence_level=item["evidence_level"],
                score=item["score"],
                eligible=item["eligible"],
                rejection_reason=item["rejection_reason"],
            )
            for item in payload["considered"]
        ],
        request=valid.request,
    )

    assert reconstructed.score != valid.score
    assert router.validate_decision(reconstructed) == valid


@pytest.mark.parametrize(
    "status",
    [
        ProviderStatus.DEGRADED,
        ProviderStatus.RATE_LIMITED,
        ProviderStatus.UNAVAILABLE,
    ],
)
def test_author_conflict_precedes_generic_provider_status(status: ProviderStatus):
    router = ReviewerPersonaRouter(
        profiles=[profile()],
        providers=[
            ReviewerProvider(
                provider_id="coderabbit",
                status=status,
                compatibility={"coderabbit-style": 0.90},
            ),
            ReviewerProvider(
                provider_id="qodo",
                status=ProviderStatus.AVAILABLE,
                compatibility={"coderabbit-style": 0.90},
            ),
        ],
    )
    decision = router.route(
        ReviewRequest(
            requested_reviewer="coderabbit",
            profile_id="coderabbit-style",
            head_sha=SHA,
            author_engine="coderabbit",
            require_independent=True,
        )
    )

    assert decision.executed_by == "qodo"
    assert decision.fallback_reason == FallbackReason.AUTHOR_CONFLICT


def test_profile_incompatibility_precedes_generic_provider_status():
    router = ReviewerPersonaRouter(
        profiles=[profile()],
        providers=[
            ReviewerProvider(
                provider_id="coderabbit",
                status=ProviderStatus.RATE_LIMITED,
                compatibility={"coderabbit-style": 0.50},
            ),
            ReviewerProvider(
                provider_id="qodo",
                status=ProviderStatus.AVAILABLE,
                compatibility={"coderabbit-style": 0.90},
            ),
        ],
    )
    decision = router.route(
        ReviewRequest(
            requested_reviewer="coderabbit",
            profile_id="coderabbit-style",
            head_sha=SHA,
        )
    )

    assert decision.fallback_reason == FallbackReason.PROFILE_INCOMPATIBLE


def test_candidate_and_route_numeric_fields_fail_closed():
    with pytest.raises(ReviewerRoutingError, match="candidate score"):
        CandidateAssessment(
            provider_id="qodo",
            status=ProviderStatus.AVAILABLE,
            compatibility=0.90,
            evidence_level=EvidenceLevel.PROXY_HIGH,
            score=2.0,
            eligible=True,
        )

    assessment = CandidateAssessment(
        provider_id="qodo",
        status=ProviderStatus.AVAILABLE,
        compatibility=0.90,
        evidence_level=EvidenceLevel.PROXY_HIGH,
        score=0.90,
        eligible=True,
    )
    with pytest.raises(ReviewerRoutingError, match="route score"):
        RouteDecision(
            requested_reviewer="qodo",
            executed_by="qodo",
            profile_id="coderabbit-style",
            profile_version="1",
            head_sha=SHA,
            native_review=False,
            evidence_level=EvidenceLevel.PROXY_HIGH,
            fallback_reason=None,
            fallback_hops=0,
            score=float("nan"),
            considered=[assessment],
        )


@pytest.mark.parametrize(
    "path",
    [
        "../secret.py",
        "nested/../secret.py",
        "..\\secret.py",
        "C:\\repo\\file.py",
        "C:/repo/file.py",
        "\\\\server\\share\\file.py",
        "/absolute/file.py",
    ],
)
def test_finding_rejects_absolute_and_traversal_paths(path: str):
    with pytest.raises(ReviewerRoutingError, match="repository-relative"):
        finding(path)


def test_finding_accepts_repository_relative_posix_path():
    assert finding("cml/reviewer_router.py").path == "cml/reviewer_router.py"
