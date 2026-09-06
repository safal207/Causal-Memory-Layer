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
SPEC = importlib.util.spec_from_file_location("liminal_recall_ccloud_evidence_plaintext", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_identity_falls_back_to_redacted_plain_text(monkeypatch) -> None:
    commands: list[list[str]] = []
    plain_output = (
        "Logged in as: operator@example.com\n"
        "Organization ID: 12345678-1234-4234-8234-123456789abc\n"
        "Console: https://cockroachlabs.cloud/orgs/example\n"
    )

    def fake_run(command):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, plain_output, "")

    monkeypatch.setattr(MODULE, "_run", fake_run)

    payload, command = MODULE._run_identity(["ccloud", "auth", "whoami"])
    serialized = json.dumps(MODULE._redact(payload), sort_keys=True)

    assert command == ["ccloud", "auth", "whoami"]
    assert payload["format"] == "plain_text"
    assert "operator@example.com" not in serialized
    assert "12345678-1234-4234-8234-123456789abc" not in serialized
    assert "https://cockroachlabs.cloud" not in serialized
    assert commands == [
        ["ccloud", "auth", "whoami", "-o", "json"],
        ["ccloud", "auth", "whoami", "--output", "json"],
        ["ccloud", "auth", "whoami"],
    ]
