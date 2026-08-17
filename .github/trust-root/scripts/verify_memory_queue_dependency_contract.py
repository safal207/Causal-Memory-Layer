#!/usr/bin/env python3
"""Fail closed when protected Memory Queue dependency installs are not hash-bound."""

from __future__ import annotations

from pathlib import Path
import re
import shlex
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
PIP_COMMAND_RE = re.compile(r"^pip(?:\d+(?:\.\d+)*)?$")
CANONICAL_PIP_PREFIX = ("python", "-m", "pip", "install")
CANONICAL_PIP_FLAGS = {"--require-hashes", "--only-binary=:all:"}


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


def _is_pip_install(tokens: list[str]) -> bool:
    if len(tokens) >= 4:
        module = tokens[2]
        if (
            tokens[1] == "-m"
            and PIP_COMMAND_RE.fullmatch(module)
            and tokens[3] == "install"
        ):
            return True
    return (
        len(tokens) >= 2
        and PIP_COMMAND_RE.fullmatch(tokens[0]) is not None
        and tokens[1] == "install"
    )


def _require_hash_enforced_workflow(path: Path) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    expected_files = [str(BOOTSTRAP), str(REQUIREMENTS)]
    observed_files: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise DependencyContractError(
                f"{path} contains an unparsable shell command: {line}"
            ) from exc
        if not tokens or not _is_pip_install(tokens):
            continue
        if tuple(tokens[:4]) != CANONICAL_PIP_PREFIX:
            raise DependencyContractError(
                f"{path} uses a noncanonical pip installer command: {line}"
            )

        args = tokens[4:]
        if any(token in {"&&", "||", ";", "|"} for token in args):
            raise DependencyContractError(
                f"{path} pip install must not chain shell commands: {line}"
            )
        requirement_tokens = [
            (index, token)
            for index, token in enumerate(args)
            if token == "--requirement"
            or token == "-r"
            or token.startswith("--requirement=")
        ]
        if len(requirement_tokens) != 1 or requirement_tokens[0][1] != "--requirement":
            raise DependencyContractError(
                f"{path} pip install must use exactly one --requirement argument: {line}"
            )
        requirement_index = requirement_tokens[0][0]
        if requirement_index + 1 >= len(args):
            raise DependencyContractError(
                f"{path} pip install is missing its --requirement value: {line}"
            )
        requirement_file = args[requirement_index + 1]
        if requirement_file not in expected_files:
            raise DependencyContractError(
                f"{path} pip install must consume an exact protected requirement file: {line}"
            )

        remaining = [
            token
            for index, token in enumerate(args)
            if index not in {requirement_index, requirement_index + 1}
        ]
        if len(remaining) != len(CANONICAL_PIP_FLAGS) or set(remaining) != CANONICAL_PIP_FLAGS:
            raise DependencyContractError(
                f"{path} pip install must contain only the canonical integrity flags: {line}"
            )
        observed_files.append(requirement_file)

    if sorted(observed_files) != sorted(expected_files):
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
