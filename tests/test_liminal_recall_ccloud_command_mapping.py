from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "hackathons"
    / "liminal-recall"
    / "scripts"
    / "ccloud_evidence.py"
)
SPEC = importlib.util.spec_from_file_location("liminal_recall_ccloud_mapping", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_organization_evidence_uses_supported_settings_command(monkeypatch, tmp_path) -> None:
    executed: list[list[str]] = []

    def fake_run(command):
        executed.append(command)
        return subprocess.CompletedProcess(command, 0, "ccloud 0.6.12\n", "")

    def fake_fallback(command):
        executed.append(command)
        return {"ok": True}, command

    monkeypatch.setattr(MODULE.shutil, "which", lambda _: "/usr/local/bin/ccloud")
    monkeypatch.setattr(MODULE, "_run", fake_run)
    monkeypatch.setattr(MODULE, "_run_with_fallback", fake_fallback)
    monkeypatch.setattr(MODULE, "_write_evidence", lambda output, evidence: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ccloud_evidence.py",
            "--cluster",
            "redacted-cluster",
            "--output",
            str(tmp_path / "evidence.json"),
        ],
    )

    assert MODULE.main() == 0
    assert ["ccloud", "organization", "get"] not in executed
    assert ["ccloud", "settings"] in executed
