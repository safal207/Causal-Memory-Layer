from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
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

SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)postgres(?:ql)?://[^\s\"']+"),
    re.compile(r"(?i)https?://[^\s\"']+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(?:password|secret|token|api[_-]?key)\s*[=:]\s*[^\s,;\"']+"),
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"),
    re.compile(r"(?im)^\s*(?:id|[a-z0-9 _-]+\bid|[a-z0-9_-]+_id)\s*[:=]\s*[^\s,;\"']+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
)

FORBIDDEN_AFTER_REDACTION = (
    re.compile(r"(?i)postgres(?:ql)?://[^\s\"']+@"),
    re.compile(r"(?i)https?://[^\s\"']+"),
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, capture_output=True, text=True)


def _run_json(base_command: list[str]) -> tuple[Any, list[str]]:
    """Run a ccloud command using the supported structured-output flag."""

    failures: list[str] = []
    for output_args in (["-o", "json"], ["--output", "json"]):
        command = [*base_command, *output_args]
        try:
            completed = _run(command)
            return json.loads(completed.stdout), command
        except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
            failures.append(f"{' '.join(command)}: {type(exc).__name__}")

    raise RuntimeError(
        "ccloud did not return valid JSON with either structured-output flag: "
        + "; ".join(failures)
    )


def _sanitize_string(value: str) -> str:
    sanitized = value
    for pattern in SENSITIVE_VALUE_PATTERNS:
        sanitized = pattern.sub("[REDACTED]", sanitized)
    return sanitized


def _is_sensitive_key(key: str) -> bool:
    normalized_key = key.casefold()
    return any(part in normalized_key for part in SENSITIVE_KEY_PARTS) or (
        normalized_key in {"id", "email", "url"}
        or normalized_key.endswith(("_id", "_email", "_url"))
    )


def _redact(value: Any, key: str = "") -> Any:
    if _is_sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(item_key): _redact(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _sanitize_string(value)
    return value


def _run_with_fallback(base_command: list[str]) -> tuple[Any, list[str]]:
    """Prefer JSON output, but safely retain legacy plain-text output."""

    try:
        return _run_json(base_command)
    except RuntimeError as structured_error:
        try:
            completed = _run(base_command)
        except subprocess.CalledProcessError as plain_error:
            raise structured_error from plain_error

        plain_output = _sanitize_string(completed.stdout.strip())
        if not plain_output:
            raise structured_error
        return {"format": "plain_text", "output": plain_output}, base_command


def _run_identity(base_command: list[str]) -> tuple[Any, list[str]]:
    """Backward-compatible alias for callers of the old identity helper."""

    return _run_with_fallback(base_command)


def _assert_sanitized(serialized: str) -> None:
    for pattern in FORBIDDEN_AFTER_REDACTION:
        if pattern.search(serialized):
            raise RuntimeError(
                "refusing to write ccloud evidence because a credential-like value remains"
            )


def _write_evidence(output: Path, evidence: dict[str, Any]) -> None:
    canonical = json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    _assert_sanitized(canonical)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(canonical, encoding="utf-8")

    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(
        f"{digest}  {output.name}\n",
        encoding="utf-8",
    )


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

    if shutil.which("ccloud") is None:
        raise SystemExit("ccloud CLI is required and was not found on PATH")

    base_commands = {
        "identity": ["ccloud", "auth", "whoami"],
        "organization": ["ccloud", "settings"],
        "cluster": ["ccloud", "cluster", "info", args.cluster],
    }
    if args.dry_run:
        print(
            json.dumps(
                {name: [*command, "-o", "json"] for name, command in base_commands.items()},
                indent=2,
            )
        )
        return 0

    ccloud_version = _sanitize_string(_run(["ccloud", "version"]).stdout.strip())
    results: dict[str, Any] = {}
    executed_commands: dict[str, list[str]] = {}
    for name, command in base_commands.items():
        payload, executed = _run_with_fallback(command)
        results[name] = _redact(payload)
        executed_commands[name] = executed

    evidence = {
        "schema_version": "liminal-recall-ccloud-evidence-v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "tool": "ccloud CLI",
        "tool_version": ccloud_version,
        "purpose": "Agent-readable cluster identity and deployment-state evidence",
        "commands": executed_commands,
        **results,
    }

    output = Path(args.output)
    _write_evidence(output, evidence)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
