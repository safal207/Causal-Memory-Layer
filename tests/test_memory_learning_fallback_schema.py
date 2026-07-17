from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / ".github/trust-root/scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

core = importlib.import_module("memory_learning_core")
fallback = importlib.import_module("memory_learning_fallback")

REPOSITORY = "safal207/Causal-Memory-Layer"
HEAD = "a" * 40
MERGE = "b" * 40


def pack() -> dict:
    return core.build_memory_pack(
        repository=REPOSITORY,
        pull={
            "number": 184,
            "title": "docs: probe",
            "body": "## Summary\nProbe.",
            "merged": True,
            "merged_at": "2026-07-17T10:21:54Z",
            "merge_commit_sha": MERGE,
            "html_url": "https://example.invalid/pull/184",
            "head": {"sha": HEAD, "ref": "agent/probe"},
            "base": {"ref": "main"},
        },
        files=[{"filename": "docs/probe.md", "status": "added"}],
        reviews=[],
        check_runs=[],
    )


def test_fallback_rejects_unbound_unknown_top_level_field() -> None:
    payload = pack()
    payload["unbound"] = "must not survive"

    with pytest.raises(core.LearningLoopError, match="invalid top-level fields"):
        fallback._load_exact_pack(
            json.dumps(payload),
            repository=REPOSITORY,
            head_sha=HEAD,
            merge_sha=MERGE,
        )


def test_fallback_rejects_unknown_nested_schema_field() -> None:
    payload = pack()
    payload["manifest"]["unbound"] = True

    with pytest.raises(core.LearningLoopError, match="invalid manifest fields"):
        fallback._load_exact_pack(
            json.dumps(payload),
            repository=REPOSITORY,
            head_sha=HEAD,
            merge_sha=MERGE,
        )
