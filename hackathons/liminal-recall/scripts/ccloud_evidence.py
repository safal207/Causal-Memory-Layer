from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SENSITIVE_KEY_PARTS = {
    "api_key",
    "certificate",
    "connection",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}


def _run_json(command: list[str]) -> Any:
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _redact(value: Any, key: str = "") -> Any:
    normalized_key = key.casefold()
    if any(part in normalized_key for part in SENSITIVE_KEY_PARTS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture redacted, machine-readable ccloud evidence for the hackathon submission."
    )
    parser.add_argument("--cluster", required=True, help="CockroachDB Cloud cluster name or ID")
    parser.add_argument(
        "--output",
        default="evidence/ccloud-evidence.json",
        help="Path for the redacted evidence manifest",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the ccloud commands without executing them",
    )
    args = parser.parse_args()

    commands = {
        "identity": ["ccloud", "auth", "whoami", "-o", "json"],
        "cluster": ["ccloud", "cluster", "get", args.cluster, "-o", "json"],
    }
    if args.dry_run:
        print(json.dumps(commands, indent=2))
        return 0

    evidence = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "tool": "ccloud CLI",
        "purpose": "Agent-readable cluster identity and deployment-state evidence",
        "commands": commands,
        "identity": _redact(_run_json(commands["identity"])),
        "cluster": _redact(_run_json(commands["cluster"])),
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
