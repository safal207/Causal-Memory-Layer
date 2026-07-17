from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_retrieval_workflow_uses_only_trusted_exact_base_code() -> None:
    workflow = (ROOT / ".github/workflows/memory-retrieval.yml").read_text(
        encoding="utf-8"
    )
    entrypoint = (
        ROOT
        / ".github/trust-root/scripts/memory_retrieval_hardened_loop.py"
    ).read_text(encoding="utf-8")
    hardened = (
        ROOT / ".github/trust-root/scripts/memory_retrieval_hardened.py"
    ).read_text(encoding="utf-8")
    adapter = (
        ROOT / ".github/trust-root/scripts/memory_retrieval_github.py"
    ).read_text(encoding="utf-8")
    core = (
        ROOT / ".github/trust-root/scripts/memory_retrieval_core.py"
    ).read_text(encoding="utf-8")

    assert "pull_request_target:" in workflow
    assert "types: [opened, reopened, synchronize, edited, ready_for_review]" in workflow
    assert "workflow_dispatch:" not in workflow
    assert "inputs.pull_number" not in workflow
    assert "permissions: {}" in workflow
    assert "contents: read" in workflow
    assert "pull-requests: write" in workflow
    assert "issues: write" not in workflow
    assert "contents: write" not in workflow
    assert "actions: write" not in workflow
    assert "cancel-in-progress: true" in workflow
    assert "ref: ${{ github.event.pull_request.base.sha }}" in workflow
    assert "|| github.sha" not in workflow
    assert "github.event.pull_request.head" not in workflow
    assert "persist-credentials: false" in workflow
    assert "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10" in workflow
    assert "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1" in workflow
    assert (
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        in workflow
    )
    assert "memory_retrieval_hardened_loop.py" in workflow
    assert "memory_retrieval_loop.py" not in workflow

    for source in (entrypoint, hardened, adapter, core):
        assert "subprocess" not in source
        assert "eval(" not in source
        assert "exec(" not in source
    assert "BOT_LOGIN = \"github-actions[bot]\"" in adapter
    assert "privacy_summary_redacted" in hardened
    assert "reconcile_managed_comment" in hardened
    assert "issues/comments/{comment_id}" in hardened
    assert "approval_authority" in entrypoint
    assert "merge_authority" in entrypoint
    assert "execution_authority" in entrypoint


def test_retrieval_runtime_never_reads_pr_patches_or_review_comments() -> None:
    adapter = (
        ROOT / ".github/trust-root/scripts/memory_retrieval_github.py"
    ).read_text(encoding="utf-8")
    hardened = (
        ROOT / ".github/trust-root/scripts/memory_retrieval_hardened.py"
    ).read_text(encoding="utf-8")

    assert "/pulls/{number}/files" in adapter
    for source in (adapter, hardened):
        assert "/pulls/{number}/comments" not in source
        assert "/pulls/{number}/reviews" not in source
        assert 'raw.get("patch")' not in source
        assert 'raw.get("diff")' not in source
        assert "fetch_pr_patch" not in source
        assert "fetch_pr_file_patch" not in source
