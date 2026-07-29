from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_mcp_sdk_adapter(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    script = root / "docs/experimental/caep/mcp_sdk_adapter/run_adapter.py"
    output = tmp_path / "bundle.json"
    completed = subprocess.run(
        [sys.executable, str(script), "--output", str(output)],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    summary = json.loads(completed.stdout.strip().splitlines()[-1])
    bundle = json.loads(output.read_text(encoding="utf-8"))
    assert summary["transport"] == "mcp-stdio"
    assert summary["caep_validation"] == "valid"
    assert summary["happy"] == "verified"
    assert summary["diverged"] == "diverged"
    assert summary["recovered"] == "verified"
    assert bundle["transport"] == "mcp-stdio"
    assert bundle["protocol_version"] != "unknown"
    assert bundle["recovery_path"]["recovered_record"]["causal_parent_ids"] == [
        "mcp_sdk_duplicate_diverged"
    ]
