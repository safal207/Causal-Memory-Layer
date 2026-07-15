from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/reviewer-fallback.yml"
CORE = ROOT / ".github/trust-root/scripts/reviewer_fallback.py"
ENTRYPOINT = ROOT / ".github/trust-root/scripts/reviewer_fallback_entrypoint.py"


def test_reviewer_fallback_workflow_is_trusted_default_branch_only():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "pull_request_target" not in text
    assert "issue_comment:" in text
    assert "pull_request_review:" in text
    assert "pull_request_review_comment:" in text
    assert "types: [created, edited]" in text
    assert "types: [submitted, edited]" in text
    assert "ref: ${{ github.event.repository.default_branch }}" in text
    assert "persist-credentials: false" in text
    assert "github.event.pull_request.head" not in text
    assert "github.event.issue.pull_request != null" in text


def test_reviewer_fallback_workflow_has_least_privilege_and_serialization():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "\npermissions: {}\n" in text
    assert "actions: read" in text
    assert "contents: read" in text
    assert "pull-requests: read" in text
    assert "issues: write" in text
    assert "statuses: write" in text
    assert "cancel-in-progress: false" in text
    assert (
        "cml-reviewer-fallback-${{ github.repository }}-"
        "${{ github.event.issue.number || github.event.pull_request.number }}"
        in text
    )


def test_reviewer_fallback_workflow_pins_actions_and_exact_attempt_evidence():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10" in text
    assert "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1" in text
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in text
    assert "/attempts/${{ github.run_attempt }}" in text
    assert "${{ github.run_id }}-${{ github.run_attempt }}" in text
    assert "if: always()" in text
    assert "if-no-files-found: error" in text
    assert "CML_EVENT_NAME: ${{ github.event_name }}" in text


def test_reviewer_fallback_workflow_runs_only_for_canonical_provider_logins():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "github.event_name == 'issue_comment'" in text
    assert "github.event_name == 'pull_request_review'" in text
    assert "github.event_name == 'pull_request_review_comment'" in text
    assert "github.event.comment.user.login == 'coderabbitai[bot]'" in text
    assert "github.event.review.user.login == 'coderabbitai[bot]'" in text
    assert "github.event.comment.user.login == 'qodo-code-review[bot]'" in text
    assert "github.event.review.user.login == 'qodo-code-review[bot]'" in text
    assert "contains(github.event.comment.body" not in text
    assert "Review limit reached" not in text
    assert ".github/trust-root/scripts/reviewer_fallback_entrypoint.py" in text
    assert "python .github/trust-root/scripts/reviewer_fallback.py" not in text


def test_reviewer_fallback_core_is_intrinsically_strict():
    core_text = CORE.read_text(encoding="utf-8")
    assert 'WORKFLOW_NAME = "CML Reviewer Fallback"' in core_text
    assert 'WORKFLOW_PATH = ".github/workflows/reviewer-fallback.yml"' in core_text
    assert "workflow artifact pagination exceeded the safe bound" in core_text
    assert "REJECTED_EDITED_QODO_RESULT" in core_text
    assert "exactly one structured reviewed-commit field" in core_text
    assert 'if head_sha is None or evidence.get("passed") is True:' in core_text
    assert 'state = "success"' not in core_text
    assert "is_coderabbit = _matches_identity(" in core_text
    assert "if _trusted_actions_comment(comment)" in core_text


def test_reviewer_fallback_entrypoint_is_a_bounded_event_adapter():
    entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
    assert "SUPPORTED_EVENT_NAMES" in entrypoint
    assert '"issue_comment"' in entrypoint
    assert '"pull_request_review"' in entrypoint
    assert '"pull_request_review_comment"' in entrypoint
    assert "normalize_event_payload" in entrypoint
    assert "MultiSurfaceGitHubApi" in entrypoint
    assert "ALLOWED_ARTIFACT_RUN_EVENTS" in entrypoint
    assert "core.process_event(" in entrypoint
    assert "core._extract_reviewed_sha =" not in entrypoint
    assert "core._publish_commit_status =" not in entrypoint
    assert "core.GitHubApi =" not in entrypoint
