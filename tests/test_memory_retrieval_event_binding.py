from __future__ import annotations

import importlib
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / ".github/trust-root/scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

core = importlib.import_module("memory_retrieval_core")
loop = importlib.import_module("memory_retrieval_hardened_loop")


def test_realistic_pull_request_webhook_binds_top_level_number() -> None:
    event = {
        "action": "opened",
        "number": 199,
        "pull_request": {
            "base": {"ref": "main", "sha": "a" * 40},
            "head": {"ref": "feature/live-proof", "sha": "b" * 40},
        },
        "repository": {"full_name": "safal207/Causal-Memory-Layer"},
    }

    assert loop.pull_number_from_event(event) == 199


def test_matching_nested_number_is_allowed_but_not_required() -> None:
    assert loop.pull_number_from_event(
        {"number": 42, "pull_request": {"number": 42}}
    ) == 42


def test_nested_number_cannot_override_top_level_binding() -> None:
    with pytest.raises(core.RetrievalError, match="binding mismatch"):
        loop.pull_number_from_event(
            {"number": 42, "pull_request": {"number": 43}}
        )


def test_nested_only_number_is_rejected() -> None:
    with pytest.raises(core.RetrievalError, match="event number"):
        loop.pull_number_from_event({"pull_request": {"number": 42}})


@pytest.mark.parametrize("value", [None, True, False, 0, -1, "42", 42.0])
def test_top_level_number_must_be_a_positive_json_integer(value: object) -> None:
    with pytest.raises(core.RetrievalError, match="event number"):
        loop.pull_number_from_event(
            {"number": value, "pull_request": {}}
        )


def test_pull_request_object_is_required() -> None:
    with pytest.raises(core.RetrievalError, match="pull_request"):
        loop.pull_number_from_event({"number": 42})
