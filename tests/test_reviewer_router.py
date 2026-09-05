from __future__ import annotations

import pytest

from cml.reviewer_router import (
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

SHA = "a" * 40


def profiles():
    return [
        ReviewerProfile(
            profile_id="codex-style",
            version="1",
            rubric=(
                "Trace concrete execution paths.",
                "Require a minimal regression test.",
            ),
        ),
        ReviewerProfile(
            profile_id="coderabbit-style",
            version="1",
            rubric=(
                "Review the complete diff.",
                "Separate blockers from nits.",
            ),
        ),
    ]


def provider(
    provider_id,
    *,
    status=ProviderStatus.AVAILABLE,
    native=(),
    compatibility=None,
    quality=1.0,
    budget=1.0,
):
    return ReviewerProvider(
        provider_id=provider_id,
        status=status,
        native_profiles=frozenset(native),
        compatibility=compatibility or {},
        historical_quality=quality,
        remaining_budget=budget,
    )


def test_native_route_preserves_provider_identity():
    router = ReviewerPersonaRouter(
        profiles=profiles(),
        providers=[
            provider("codex", native=("codex-style",)),
            provider("qodo", compatibility={"codex-style": 0.9}),
        ],
    )
    decision = router.route(
        ReviewRequest(
            requested_reviewer="codex",
            profile_id="codex-style",
            head_sha=SHA,
        )
    )
    assert decision.executed_by == "codex"
    assert decision.native_review is True
    assert decision.evidence_level == EvidenceLevel.NATIVE
    assert decision.fallback_reason is None
    assert decision.to_dict()["merge_authority"] is False


def test_rate_limited_reviewer_routes_profile_to_qodo():
    router = ReviewerPersonaRouter(
        profiles=profiles(),
        providers=[
            provider(
                "coderabbit",
                status=ProviderStatus.RATE_LIMITED,
                native=("coderabbit-style",),
            ),
            provider(
                "qodo",
                native=("codex-style",),
                compatibility={"coderabbit-style": 0.91},
                quality=0.95,
                budget=0.8,
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
    assert decision.executed_by == "qodo"
    assert decision.native_review is False
    assert decision.evidence_level == EvidenceLevel.PROXY_HIGH
    assert decision.fallback_reason == FallbackReason.RATE_LIMITED
    assert decision.fallback_hops == 1
    prompt = router.render_execution_prompt(decision)
    assert "Execution provider: qodo" in prompt
    assert "Requested reviewer: coderabbit" in prompt
    assert "never claim to be the requested reviewer" in prompt


def test_author_engine_cannot_be_sole_independent_reviewer():
    router = ReviewerPersonaRouter(
        profiles=profiles(),
        providers=[
            provider("codex", native=("codex-style",)),
            provider("qodo", compatibility={"codex-style": 0.88}),
        ],
    )
    decision = router.route(
        ReviewRequest(
            requested_reviewer="codex",
            profile_id="codex-style",
            head_sha=SHA,
            author_engine="codex",
            require_independent=True,
        )
    )
    assert decision.executed_by == "qodo"
    assert decision.fallback_reason == FallbackReason.AUTHOR_CONFLICT


def test_deterministic_tie_break_uses_provider_id():
    router = ReviewerPersonaRouter(
        profiles=profiles(),
        providers=[
            provider(
                "coderabbit",
                status=ProviderStatus.UNAVAILABLE,
                native=("coderabbit-style",),
            ),
            provider("zeta", compatibility={"coderabbit-style": 0.9}),
            provider("alpha", compatibility={"coderabbit-style": 0.9}),
        ],
    )
    decision = router.route(
        ReviewRequest(
            requested_reviewer="coderabbit",
            profile_id="coderabbit-style",
            head_sha=SHA,
        )
    )
    assert decision.executed_by == "alpha"


def test_degraded_provider_requires_explicit_degraded_evidence():
    router = ReviewerPersonaRouter(
        profiles=profiles(),
        providers=[
            provider(
                "coderabbit",
                status=ProviderStatus.RATE_LIMITED,
                native=("coderabbit-style",),
            ),
            provider(
                "qodo",
                status=ProviderStatus.DEGRADED,
                compatibility={"coderabbit-style": 0.95},
            ),
        ],
    )
    with pytest.raises(ReviewerRoutingError, match="no eligible reviewer"):
        router.route(
            ReviewRequest(
                requested_reviewer="coderabbit",
                profile_id="coderabbit-style",
                head_sha=SHA,
            )
        )
    decision = router.route(
        ReviewRequest(
            requested_reviewer="coderabbit",
            profile_id="coderabbit-style",
            head_sha=SHA,
            minimum_evidence=EvidenceLevel.DEGRADED,
        )
    )
    assert decision.evidence_level == EvidenceLevel.DEGRADED
    assert decision.executed_by == "qodo"


def test_invalid_sha_and_unknown_profile_fail_closed():
    with pytest.raises(ReviewerRoutingError, match="40-character"):
        ReviewRequest(
            requested_reviewer="codex",
            profile_id="codex-style",
            head_sha="abc",
        )
    router = ReviewerPersonaRouter(
        profiles=profiles(),
        providers=[provider("codex", native=("codex-style",))],
    )
    with pytest.raises(ReviewerRoutingError, match="unknown reviewer profile"):
        router.route(
            ReviewRequest(
                requested_reviewer="codex",
                profile_id="missing-style",
                head_sha=SHA,
            )
        )


def test_fallback_can_be_disabled_and_cannot_chain():
    router = ReviewerPersonaRouter(
        profiles=profiles(),
        providers=[
            provider(
                "coderabbit",
                status=ProviderStatus.RATE_LIMITED,
                native=("coderabbit-style",),
            ),
            provider("qodo", compatibility={"coderabbit-style": 0.9}),
        ],
    )
    with pytest.raises(ReviewerRoutingError, match="fallback is disabled"):
        router.route(
            ReviewRequest(
                requested_reviewer="coderabbit",
                profile_id="coderabbit-style",
                head_sha=SHA,
                max_fallback_hops=0,
            )
        )
    with pytest.raises(ReviewerRoutingError, match="0 or 1"):
        ReviewRequest(
            requested_reviewer="coderabbit",
            profile_id="coderabbit-style",
            head_sha=SHA,
            max_fallback_hops=2,
        )


def test_duplicate_provider_and_unknown_compatibility_profile_fail():
    with pytest.raises(ReviewerRoutingError, match="duplicate reviewer provider"):
        ReviewerPersonaRouter(
            profiles=profiles(),
            providers=[provider("codex"), provider("codex")],
        )
    with pytest.raises(ReviewerRoutingError, match="unknown profiles"):
        ReviewerPersonaRouter(
            profiles=profiles(),
            providers=[provider("codex", compatibility={"ghost-style": 0.9})],
        )


def test_proxy_cannot_be_serialized_as_native():
    with pytest.raises(ReviewerRoutingError, match="proxy executor"):
        RouteDecision(
            requested_reviewer="coderabbit",
            executed_by="qodo",
            profile_id="coderabbit-style",
            profile_version="1",
            head_sha=SHA,
            native_review=True,
            evidence_level=EvidenceLevel.NATIVE,
            fallback_reason=FallbackReason.RATE_LIMITED,
            fallback_hops=1,
            score=1.0,
            considered=(),
        )


def test_normalized_finding_keeps_executor_and_profile_separate():
    finding = NormalizedReviewFinding(
        code="CML-REVIEW-CORRECTNESS",
        severity="P1",
        category="correctness",
        path="cml/reviewer_router.py",
        message="A route can misrepresent identity.",
        failure_path="Proxy output is recorded as native.",
        counterexample="requested=coderabbit, executed_by=qodo, native=true",
        regression_test="Construct a proxy decision with native_review=true.",
        smallest_remediation="Reject mismatched native identity.",
        confidence=0.95,
        executed_by="qodo",
        profile_id="coderabbit-style",
        head_sha=SHA,
    )
    payload = finding.to_dict()
    assert payload["executed_by"] == "qodo"
    assert payload["profile_id"] == "coderabbit-style"
    assert payload["head_sha"] == SHA


def test_yaml_configuration_routes_proxy():
    router = ReviewerPersonaRouter.from_yaml_string(
        """
profiles:
  - profile_id: coderabbit-style
    version: '1'
    rubric:
      - Review the complete diff.
providers:
  - provider_id: coderabbit
    status: RATE_LIMITED
    native_profiles: [coderabbit-style]
  - provider_id: qodo
    status: AVAILABLE
    compatibility:
      coderabbit-style: 0.9
"""
    )
    decision = router.route(
        ReviewRequest(
            requested_reviewer="coderabbit",
            profile_id="coderabbit-style",
            head_sha=SHA,
        )
    )
    assert decision.executed_by == "qodo"


def test_fallback_provider_never_gets_native_evidence():
    router = ReviewerPersonaRouter(
        profiles=profiles(),
        providers=[
            provider(
                "coderabbit",
                status=ProviderStatus.RATE_LIMITED,
                native=("coderabbit-style",),
            ),
            provider("qodo", native=("coderabbit-style",)),
        ],
    )
    decision = router.route(
        ReviewRequest(
            requested_reviewer="coderabbit",
            profile_id="coderabbit-style",
            head_sha=SHA,
            minimum_evidence=EvidenceLevel.PROXY_HIGH,
        )
    )
    assert decision.executed_by == "qodo"
    assert decision.native_review is False
    assert decision.evidence_level == EvidenceLevel.PROXY_HIGH


def test_yaml_duplicate_keys_fail_closed():
    with pytest.raises(ReviewerRoutingError, match="duplicate key"):
        ReviewerPersonaRouter.from_yaml_string(
            """
profiles:
  - profile_id: codex-style
    profile_id: coderabbit-style
    version: '1'
    rubric: [Review the diff.]
providers: []
"""
        )
