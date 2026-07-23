from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "hackathons"
    / "liminal-recall"
    / "scripts"
    / "ccloud_evidence.py"
)
SPEC = importlib.util.spec_from_file_location("liminal_recall_ccloud_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_redaction_removes_sensitive_keys_and_values() -> None:
    private_key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "super-secret-material\n"
        "-----END PRIVATE KEY-----"
    )
    payload = {
        "password": "do-not-publish",
        "safe": "postgresql://user:password@example.com:26257/defaultdb",
        "nested": {
            "description": "Bearer abcdefghijklmnopqrstuvwxyz",
            "certificate_text": private_key,
        },
    }

    serialized = json.dumps(MODULE._redact(payload), sort_keys=True)

    assert "do-not-publish" not in serialized
    assert "postgresql://" not in serialized
    assert "abcdefghijklmnopqrstuvwxyz" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert serialized.count("[REDACTED]") >= 4


def test_dry_run_uses_current_cluster_info_command(monkeypatch, capsys) -> None:
    monkeypatch.setattr(MODULE.shutil, "which", lambda _: "/usr/local/bin/ccloud")
    monkeypatch.setattr(
        sys,
        "argv",
        ["ccloud_evidence.py", "--cluster", "liminal-recall", "--dry-run"],
    )

    assert MODULE.main() == 0
    commands = json.loads(capsys.readouterr().out)

    assert commands["identity"] == ["ccloud", "auth", "whoami", "-o", "json"]
    assert commands["organization"] == ["ccloud", "organization", "get", "-o", "json"]
    assert commands["cluster"] == [
        "ccloud",
        "cluster",
        "info",
        "liminal-recall",
        "-o",
        "json",
    ]


def test_evidence_writer_creates_integrity_sidecar(tmp_path) -> None:
    output = tmp_path / "ccloud-evidence.json"
    MODULE._write_evidence(output, {"cluster": {"name": "liminal-recall"}})

    assert output.exists()
    assert output.with_suffix(".json.sha256").exists()
    assert "liminal-recall" in output.read_text(encoding="utf-8")
