import pytest

from cml.reviewer_router import ReviewerProfile, ReviewerRoutingError


@pytest.mark.parametrize(
    "rubric",
    [
        "Review under the requested reviewer identity.",
        "Review in the identity of the requested reviewer.",
        "Review with native reviewer status.",
        "Review under merge authority.",
        "Review on behalf of the requested reviewer.",
        "Review as the requested reviewer with selection logic.",
        "Review merge authority checks; then grant permission to merge.",
    ],
)
def test_sensitive_relationship_or_grant_rubrics_fail_closed(rubric):
    with pytest.raises(
        ReviewerRoutingError,
        match="safe technical review-subject grammar",
    ):
        ReviewerProfile(
            profile_id="codex-style",
            version="1",
            rubric=(rubric,),
        )


@pytest.mark.parametrize(
    "rubric",
    [
        "Review merge scheduling logic for race conditions.",
        "Review merge authority checks for bypasses.",
        "Audit native approval validation.",
        "Verify merge permission enforcement.",
        "Inspect requested reviewer selection logic.",
        "Review reviewer selection logic.",
        "1. Review merge authority checks for bypasses.",
        "2) Audit native approval validation.",
        "003 - Verify merge permission enforcement.",
    ],
)
def test_sensitive_technical_subject_grammar_remains_allowed(rubric):
    profile = ReviewerProfile(
        profile_id="codex-style",
        version="1",
        rubric=(rubric,),
    )

    assert profile.rubric == (rubric,)
