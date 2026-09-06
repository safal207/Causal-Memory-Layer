from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "hackathons"
    / "liminal-recall"
    / "scripts"
    / "ccloud_evidence.py"
)
SPEC = importlib.util.spec_from_file_location("liminal_recall_ccloud_evidence_generic", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _plain_runner(monkeypatch, output: str) -> list[list[str]]:
    commands: list[list[str]] = []

    def fake_run(command):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(MODULE, "_run", fake_run)
    return commands


def test_organization_get_uses_plain_text_fallback(monkeypatch) -> None:
    commands = _plain_runner(
        monkeypatch,
        "Organization ID: org-12345\nOwner: operator@example.com\n",
    )

    payload, executed = MODULE._run_with_fallback(["ccloud", "organization", "get"])
    serialized = json.dumps(MODULE._redact(payload), sort_keys=True)

    assert executed == ["ccloud", "organization", "get"]
    assert payload["format"] == "plain_text"
    assert "org-12345" not in serialized
    assert "operator@example.com" not in serialized
    assert commands == [
        ["ccloud", "organization", "get", "-o", "json"],
        ["ccloud", "organization", "get", "--output", "json"],
        ["ccloud", "organization", "get"],
    ]


def test_generic_fallback_handles_invalid_json_for_cluster_command(monkeypatch) -> None:
    commands = _plain_runner(
        monkeypatch,
        "Cluster ID: 12345678-1234-4234-8234-123456789abc\n"
        "Console: https://cockroachlabs.cloud/clusters/demo\n",
    )

    payload, executed = MODULE._run_with_fallback(
        ["ccloud", "cluster", "info", "liminal-recall"]
    )
    serialized = json.dumps(MODULE._redact(payload), sort_keys=True)

    assert executed == ["ccloud", "cluster", "info", "liminal-recall"]
    assert "12345678-1234-4234-8234-123456789abc" not in serialized
    assert "https://cockroachlabs.cloud" not in serialized
    assert commands[-1] == ["ccloud", "cluster", "info", "liminal-recall"]
