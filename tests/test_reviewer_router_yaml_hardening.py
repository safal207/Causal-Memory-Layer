from __future__ import annotations

import pytest

from cml.reviewer_router import ReviewerPersonaRouter, ReviewerRoutingError


def test_yaml_boolean_probability_is_rejected():
    with pytest.raises(ReviewerRoutingError, match="not boolean"):
        ReviewerPersonaRouter.from_yaml_string(
            """
profiles:
  - profile_id: coderabbit-style
    version: '1'
    rubric: [Review the complete diff.]
providers:
  - provider_id: coderabbit
    status: RATE_LIMITED
    native_profiles: [coderabbit-style]
  - provider_id: qodo
    status: AVAILABLE
    compatibility:
      coderabbit-style: yes
"""
        )


def test_yaml_compatibility_sequence_of_pairs_is_rejected():
    with pytest.raises(ReviewerRoutingError, match="compatibility must be a mapping"):
        ReviewerPersonaRouter.from_yaml_string(
            """
profiles:
  - profile_id: coderabbit-style
    version: '1'
    rubric: [Review the complete diff.]
providers:
  - provider_id: coderabbit
    status: RATE_LIMITED
    native_profiles: [coderabbit-style]
  - provider_id: qodo
    status: AVAILABLE
    compatibility:
      - [coderabbit-style, 0.20]
      - [coderabbit-style, 0.95]
"""
        )


def test_direct_boolean_quality_is_rejected():
    with pytest.raises(ReviewerRoutingError, match="not boolean"):
        ReviewerPersonaRouter.from_dict(
            {
                "profiles": [
                    {
                        "profile_id": "codex-style",
                        "version": "1",
                        "rubric": ["Trace concrete execution paths."],
                    }
                ],
                "providers": [
                    {
                        "provider_id": "codex",
                        "status": "AVAILABLE",
                        "native_profiles": ["codex-style"],
                        "historical_quality": True,
                    }
                ],
            }
        )
