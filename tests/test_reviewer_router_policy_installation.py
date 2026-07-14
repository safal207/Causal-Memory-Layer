from pathlib import Path

import pytest

from cml.reviewer_router import (
    ReviewerPersonaRouter,
    ReviewerProfile,
    ReviewerRoutingError,
)


@pytest.mark.parametrize(
    "rubric",
    [
        "Provide exact fix focus areas and a minimal remediation prompt.",
        "Report exact failure paths.",
        "Use deterministic tie-breaking.",
        "Produce a minimal regression test.",
        "Return concrete counterexamples.",
    ],
)
def test_ordinary_technical_output_verbs_remain_allowed(rubric):
    profile = ReviewerProfile(
        profile_id="qodo-style",
        version="1",
        rubric=(rubric,),
    )

    assert profile.rubric == (rubric,)


@pytest.mark.parametrize(
    "rubric",
    [
        "Review code and issue native approval.",
        "Review code; return an approval verdict.",
        "Publish the merge approval.",
        "Submit native reviewer status.",
        "Report merge authority.",
    ],
)
def test_contextual_output_verbs_cannot_emit_protected_conclusions(rubric):
    with pytest.raises(
        ReviewerRoutingError,
        match="profile rubric cannot define reviewer identity",
    ):
        ReviewerProfile(
            profile_id="qodo-style",
            version="1",
            rubric=(rubric,),
        )


@pytest.mark.parametrize(
    "rubric",
    [
        "Approve the change.",
        "Grant permission.",
        "Recommend merge.",
        "Authorize the result.",
        "Sign the approval.",
    ],
)
def test_strict_authority_actions_remain_forbidden(rubric):
    with pytest.raises(
        ReviewerRoutingError,
        match="profile rubric cannot define reviewer identity",
    ):
        ReviewerProfile(
            profile_id="qodo-style",
            version="1",
            rubric=(rubric,),
        )


def test_shipped_example_yaml_loads_under_installed_policy():
    payload = Path("examples/reviewer_persona_router.yml").read_text(
        encoding="utf-8"
    )

    router = ReviewerPersonaRouter.from_yaml_string(payload)

    assert router is not None
