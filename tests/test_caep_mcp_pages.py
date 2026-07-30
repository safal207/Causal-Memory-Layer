from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _records(value: object) -> list[dict]:
    found: list[dict] = []
    if isinstance(value, dict):
        if value.get("profile") == "org.causal-memory-layer.caep":
            found.append(value)
        else:
            for child in value.values():
                found.extend(_records(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_records(child))
    return found


def test_public_mcp_evidence_contract() -> None:
    root = Path(__file__).resolve().parents[1]
    canonical_dir = root / "docs/experimental/caep/mcp_sdk_adapter"
    page_dir = root / "docs/pages/trust-console"

    canonical_bundle = canonical_dir / "mcp-sdk-bundle.json"
    published_bundle = page_dir / "mcp-sdk-bundle.json"
    canonical_manifest = canonical_dir / "evidence-manifest.json"
    published_manifest = page_dir / "evidence-manifest.json"

    assert canonical_bundle.read_bytes() == published_bundle.read_bytes()
    assert canonical_manifest.read_bytes() == published_manifest.read_bytes()

    bundle_bytes = published_bundle.read_bytes()
    bundle = json.loads(bundle_bytes)
    manifest = json.loads(published_manifest.read_text(encoding="utf-8"))
    digest = hashlib.sha256(bundle_bytes).hexdigest()

    assert digest == manifest["sha256"]
    assert len(bundle_bytes) == manifest["size_bytes"]
    assert manifest["bundle_file"] == "mcp-sdk-bundle.json"
    assert manifest["bundle_media_type"] == "application/json"
    assert manifest["cross_python_byte_identity"] is True
    assert manifest["python_versions"] == ["3.10", "3.11", "3.12"]
    assert bundle["transport"] == "mcp-stdio"
    assert bundle["sdk_package"] == "mcp"
    assert bundle["sdk_version"] == manifest["mcp_sdk_version"]
    assert bundle["protocol_version"] == manifest["mcp_protocol_version"]

    records = {record["episode_id"]: record for record in _records(bundle)}
    assert set(records) == {
        "mcp_sdk_happy_verified",
        "mcp_sdk_duplicate_diverged",
        "mcp_sdk_duplicate_recovered",
    }
    assert records["mcp_sdk_happy_verified"]["status"] == "verified"
    assert records["mcp_sdk_duplicate_diverged"]["verification"]["verdict"] == (
        "diverged"
    )
    recovered = records["mcp_sdk_duplicate_recovered"]
    assert recovered["status"] == "recovered"
    assert recovered["causal_parent_ids"] == ["mcp_sdk_duplicate_diverged"]
    assert recovered["verification"]["verdict"] == "verified"

    extension = recovered["extensions"][
        "org.causal-memory-layer.mcp-sdk-adapter"
    ]
    assert extension["real_mcp_session"] is True
    assert extension["independent_server_processes"] is True
    assert extension["action_server_tools"] == [
        "cancel_payment",
        "create_payment",
        "observe_order",
    ]
    assert extension["verifier_server_tools"] == ["verify_single_payment"]

    index = (page_dir / "index.html").read_text(encoding="utf-8")
    app = (page_dir / "app.js").read_text(encoding="utf-8")
    styles = (page_dir / "styles.css").read_text(encoding="utf-8")
    assert 'id="mcpDemo"' in index
    assert 'id="heroMcpDemo"' in index
    assert 'id="protocol"' in index
    assert 'src="./app.js"' in index
    assert 'href="./styles.css"' in index
    assert 'fetch("./mcp-sdk-bundle.json")' in app
    assert 'fetch("./evidence-manifest.json")' in app
    assert "manifest.sha256" in app
    assert "Published MCP evidence failed SHA-256 verification" in app
    assert "independent_server_processes" in app
    assert "Cross-Python identity" in app
    assert "@media(max-width:900px)" in styles
