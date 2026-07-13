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


def test_render_rejects_tampered_considered_evidence():
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
    forged = replace(valid, considered=[valid.considered[0], tampered_qodo])

    with pytest.raises(ReviewerRoutingError, match="recomputed"):
        router.render_execution_prompt(forged)


def test_degraded_author_conflict_preserves_explicit_cause():
    router = ReviewerPersonaRouter(
        profiles=[profile()],
        providers=[
            ReviewerProvider(
                provider_id="coderabbit",
                status=ProviderStatus.DEGRADED,
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
