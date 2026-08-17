#!/usr/bin/env python3
"""Fail closed when protected Memory Queue dependency installs are not hash-bound."""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
BOOTSTRAP = Path(".github/trust-root/memory_queue_pip_bootstrap.txt")
REQUIREMENTS = Path(".github/trust-root/memory_queue_ci_requirements.txt")
WORKFLOWS = (
    Path(".github/workflows/memory-queue-revalidation.yml"),
    Path(".github/workflows/memory-queue-review-workbench.yml"),
    Path(".github/workflows/memory-queue-semantic-acceptance.yml"),
)
HASHED_PIN_RE = re.compile(
    r"^[A-Za-z0-9_.-]+==[^\s]+\s+--hash=sha256:[0-9a-f]{64}$"
)


class DependencyContractError(ValueError):
    """Raised when a protected dependency or install loses integrity binding."""


def _require_hash_bound_file(path: Path) -> None:
    lines = (ROOT / path).read_text(encoding="utf-8").splitlines()
    requirements = [
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not requirements:
        raise DependencyContractError(f"{path} contains no requirements")
    invalid = [line for line in requirements if not HASHED_PIN_RE.fullmatch(line)]
    if invalid:
        raise DependencyContractError(
            f"{path} contains non-exact or hashless requirements: {invalid}"
        )


def _require_hash_enforced_workflow(path: Path) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    install_lines = [
        line.strip()
        for line in text.splitlines()
        if "python -m pip install" in line
    ]
    if len(install_lines) != 2:
        raise DependencyContractError(
            f"{path} must contain exactly two protected pip install commands"
        )
    expected_files = {str(BOOTSTRAP), str(REQUIREMENTS)}
    observed_files: set[str] = set()
    for line in install_lines:
        if "--require-hashes" not in line or "--only-binary=:all:" not in line:
            raise DependencyContractError(
                f"{path} pip install is not hash-enforced and wheel-only: {line}"
            )
        if "--requirement" not in line:
            raise DependencyContractError(
                f"{path} pip install must consume a protected requirement file: {line}"
            )
        for requirement_file in expected_files:
            if requirement_file in line:
                observed_files.add(requirement_file)
    if observed_files != expected_files:
        raise DependencyContractError(
            f"{path} must install both protected requirement files exactly once"
        )


def verify() -> None:
    for path in (BOOTSTRAP, REQUIREMENTS):
        _require_hash_bound_file(path)
    for path in WORKFLOWS:
        _require_hash_enforced_workflow(path)


def main() -> int:
    try:
        verify()
    except (OSError, DependencyContractError) as exc:
        print(f"CML Memory Queue dependency contract failed closed: {exc}", file=sys.stderr)
        return 2
    print("CML Memory Queue dependency contract verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
