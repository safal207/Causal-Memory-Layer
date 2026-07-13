from __future__ import annotations

import pytest

from cml.reviewer_router import (
    EvidenceLevel,
    FallbackReason,
    ProviderStatus,
    ReviewRequest,
    ReviewerPersonaRouter,
    ReviewerProfile,
    ReviewerProvider,
    ReviewerRoutingError,
)

SHA = "b" * 40


def profile() -> ReviewerProfile:
    return ReviewerProfile(
        profile_id="coderabbit-style",
        version="1",
        rubric=("Review the complete diff.",),
        minimum_compatibility=0.70,
    )


def test_evidence_threshold_has_distinct_fallback_reason():
    router = ReviewerPersonaRouter(
        profiles=[profile()],
        providers=[
            ReviewerProvider(
                provider_id="coderabbit",
                status=ProviderStatus.AVAILABLE,
                compatibility={"coderabbit-style": 0.80},
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
            minimum_evidence=EvidenceLevel.PROXY_HIGH,
        )
    )

    assert decision.executed_by == "qodo"
    assert decision.fallback_reason == FallbackReason.EVIDENCE_BELOW_MINIMUM


def test_yaml_unhashable_mapping_key_is_wrapped_fail_closed():
    with pytest.raises(ReviewerRoutingError, match="cannot parse router YAML"):
        ReviewerPersonaRouter.from_yaml_string(
            """
? [profiles, providers]
: invalid
"""
        )


def test_provider_compatibility_is_immutable_after_construction():
    provider = ReviewerProvider(
        provider_id="qodo",
        status=ProviderStatus.AVAILABLE,
        compatibility={"coderabbit-style": 0.90},
    )

    with pytest.raises(TypeError):
        provider.compatibility["coderabbit-style"] = 0.10  # type: ignore[index]

    assert provider.compatibility_for("coderabbit-style") == 0.90


def test_yaml_non_string_identity_is_rejected():
    with pytest.raises(ReviewerRoutingError, match="provider_id must be text"):
        ReviewerPersonaRouter.from_yaml_string(
            """
profiles:
  - profile_id: coderabbit-style
    version: '1'
    rubric: [Review the complete diff.]
providers:
  - provider_id: yes
    status: AVAILABLE
    compatibility:
      coderabbit-style: 0.90
"""
        )


def test_normalized_duplicate_compatibility_keys_are_rejected():
    with pytest.raises(
        ReviewerRoutingError,
        match="duplicate normalized compatibility profile",
    ):
        ReviewerProvider(
            provider_id="qodo",
            status=ProviderStatus.AVAILABLE,
            compatibility={
                "Coderabbit-Style": 0.20,
                "coderabbit-style": 0.90,
            },
        )
