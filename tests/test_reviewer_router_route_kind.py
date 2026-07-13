from cml.reviewer_router import (
    EvidenceLevel,
    ProviderStatus,
    ReviewRequest,
    ReviewerPersonaRouter,
    ReviewerProfile,
    ReviewerProvider,
)


SHA = "d" * 40


def test_zero_hop_non_native_evidence_renders_proxy_route_kind():
    router = ReviewerPersonaRouter(
        profiles=[
            ReviewerProfile(
                profile_id="codex-style",
                version="1",
                rubric=("Review the complete diff.",),
                minimum_compatibility=0.70,
            )
        ],
        providers=[
            ReviewerProvider(
                provider_id="coderabbit",
                status=ProviderStatus.AVAILABLE,
                compatibility={"codex-style": 0.90},
            )
        ],
    )

    decision = router.route(
        ReviewRequest(
            requested_reviewer="coderabbit",
            profile_id="codex-style",
            head_sha=SHA,
        )
    )

    assert decision.executed_by == "coderabbit"
    assert decision.fallback_hops == 0
    assert decision.native_review is False
    assert decision.evidence_level == EvidenceLevel.PROXY_HIGH

    prompt = router.render_execution_prompt(decision)
    assert "Route kind: proxy" in prompt
    assert "Route kind: native" not in prompt
    assert "Evidence level: PROXY_HIGH" in prompt
