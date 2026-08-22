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
INSTALL_STEP_NAME = "Install hash-bound test tooling"
CANONICAL_INSTALL_COMMANDS = tuple(
    "python -m pip install --require-hashes --only-binary=:all: "
    f"--requirement {requirement}"
    for requirement in (BOOTSTRAP, REQUIREMENTS)
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


def _leading_spaces(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _extract_install_step_commands(text: str, path: Path) -> tuple[str, ...]:
    lines = text.splitlines()
    marker = f"- name: {INSTALL_STEP_NAME}"
    matches = [index for index, line in enumerate(lines) if line.strip() == marker]
    if len(matches) != 1:
        raise DependencyContractError(
            f"{path} must contain exactly one {INSTALL_STEP_NAME!r} step"
        )

    start = matches[0]
    step_indent = _leading_spaces(lines[start])
    end = len(lines)
    for index in range(start + 1, len(lines)):
        stripped = lines[index].strip()
        if (
            stripped
            and _leading_spaces(lines[index]) <= step_indent
            and stripped.startswith("- ")
        ):
            end = index
            break

    step_lines = lines[start + 1 : end]
    run_indexes = [
        index
        for index, line in enumerate(step_lines)
        if line.strip() == "run: |" and _leading_spaces(line) == step_indent + 2
    ]
    if len(run_indexes) != 1:
        raise DependencyContractError(
            f"{path} {INSTALL_STEP_NAME!r} step must contain exactly one literal run block"
        )

    run_index = run_indexes[0]
    if any(line.strip() for line in step_lines[:run_index]):
        raise DependencyContractError(
            f"{path} {INSTALL_STEP_NAME!r} step must not contain extra configuration"
        )

    run_indent = _leading_spaces(step_lines[run_index])
    commands: list[str] = []
    for raw_line in step_lines[run_index + 1 :]:
        stripped = raw_line.strip()
        if not stripped:
            continue
        if _leading_spaces(raw_line) <= run_indent:
            raise DependencyContractError(
                f"{path} {INSTALL_STEP_NAME!r} step must contain only its run block"
            )
        if stripped.startswith("#"):
            continue
        commands.append(stripped)
    return tuple(commands)


def _require_hash_enforced_workflow(path: Path) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    install_commands = _extract_install_step_commands(text, path)
    if install_commands != CANONICAL_INSTALL_COMMANDS:
        raise DependencyContractError(
            f"{path} {INSTALL_STEP_NAME!r} commands must exactly match the protected install contract"
        )

    expected_files = [str(BOOTSTRAP), str(REQUIREMENTS)]
    observed_files: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "pip" not in line or "install" not in line:
            continue
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise DependencyContractError(
                f"{path} contains an unparsable pip install command: {line}"
            ) from exc
        if not tokens or not _is_pip_install(tokens):
            raise DependencyContractError(
                f"{path} contains a noncanonical pip install command: {line}"
            )
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
