from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def _canonical_bundle_bytes(bundle: dict) -> bytes:
    return (
        json.dumps(
            bundle,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


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
    bundle = json.loads(output.read_bytes())
    canonical_bytes = _canonical_bundle_bytes(bundle)

    assert summary["transport"] == "mcp-stdio"
    assert summary["caep_validation"] == "valid"
    assert summary["happy"] == "verified"
    assert summary["diverged"] == "diverged"
    assert summary["recovered"] == "verified"
    assert bundle["transport"] == "mcp-stdio"
    assert bundle["protocol_version"] != "unknown"
    assert bundle["sdk_package"] == "mcp"
    assert bundle["recovery_path"]["recovered_record"]["causal_parent_ids"] == [
        "mcp_sdk_duplicate_diverged"
    ]

    artifact_dir = root / (
        f"artifacts/tests/python-{sys.version_info.major}.{sys.version_info.minor}"
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_bundle = artifact_dir / "mcp-sdk-bundle.json"
    artifact_bundle.write_bytes(canonical_bytes)
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    (artifact_dir / "mcp-sdk-bundle.sha256").write_text(
        f"{digest}  mcp-sdk-bundle.json\n",
        encoding="utf-8",
    )

    canonical = root / (
        "docs/experimental/caep/mcp_sdk_adapter/mcp-sdk-bundle.json"
    )
    published = root / "docs/pages/trust-console/mcp-sdk-bundle.json"
    assert canonical.exists(), "canonical MCP evidence bundle is missing"
    assert published.exists(), "published MCP evidence bundle is missing"
    assert canonical.read_bytes() == published.read_bytes()
    assert canonical.read_bytes() == canonical_bytes
    assert hashlib.sha256(published.read_bytes()).hexdigest() == digest
