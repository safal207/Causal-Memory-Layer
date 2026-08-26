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
INSTALL_STEP_NAME = "Install hash-bound test tooling"
CANONICAL_INSTALL_COMMANDS = tuple(
    "python -m pip install --require-hashes --only-binary=:all: "
    f"--requirement {requirement}"
    for requirement in (BOOTSTRAP, REQUIREMENTS)
)
ALLOWED_PYTHON_MODULES = frozenset(
    {
        "scripts.ci.assert_exact_head",
        "pytest",
        "cml.experimental.memory_proposal_semantic_acceptance",
        "cml.experimental.memory_proposal_review_workbench",
        "scripts.ci.build_evidence_manifest",
    }
)
ALLOWED_PYTHON_SCRIPTS = frozenset(
    {
        ".github/trust-root/scripts/verify_memory_queue_dependency_contract.py",
        ".github/trust-root/scripts/memory_queue_revalidation_collect.py",
        ".github/trust-root/scripts/memory_review_workbench_collect.py",
    }
)
SHELL_CONTROL_TOKENS = frozenset({"&&", "||", ";", "|", "&"})
SHELL_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


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


def _leading_spaces(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _logical_shell_commands(
    lines: list[str], path: Path, step_name: str
) -> tuple[str, ...]:
    commands: list[str] = []
    current: list[str] = []
    heredoc_end: str | None = None

    for raw_line in lines:
        stripped = raw_line.strip()
        if heredoc_end is not None:
            if stripped == heredoc_end:
                heredoc_end = None
            continue
        if not stripped or stripped.startswith("#"):
            continue

        continued = stripped.endswith("\\")
        current.append(stripped[:-1].rstrip() if continued else stripped)
        if continued:
            continue

        command = " ".join(current).strip()
        current = []
        commands.append(command)
        heredoc = HEREDOC_RE.search(command)
        if heredoc:
            heredoc_end = heredoc.group(2)

    if heredoc_end is not None:
        raise DependencyContractError(
            f"{path} step {step_name!r} contains an unterminated heredoc"
        )
    if current:
        raise DependencyContractError(
            f"{path} step {step_name!r} contains an unterminated continuation"
        )
    return tuple(commands)


def _extract_run_blocks(text: str, path: Path) -> tuple[tuple[str, tuple[str, ...]], ...]:
    lines = text.splitlines()
    blocks: list[tuple[str, tuple[str, ...]]] = []
    step_name: str | None = None
    step_indent: int | None = None
    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        indent = _leading_spaces(line)

        if stripped.startswith("- run:"):
            raise DependencyContractError(
                f"{path} all run steps must have an explicit name"
            )

        if stripped.startswith("- name: "):
            step_name = stripped[len("- name: ") :].strip()
            step_indent = indent
            index += 1
            continue

        if (
            step_indent is not None
            and indent == step_indent
            and stripped.startswith("- ")
            and not stripped.startswith("- name: ")
        ):
            step_name = None
            step_indent = None

        if stripped.startswith("run:"):
            if step_name is None or step_indent is None or indent != step_indent + 2:
                raise DependencyContractError(
                    f"{path} contains a run block outside a named step"
                )
            suffix = stripped[len("run:") :].strip()
            if suffix == "|":
                run_indent = indent
                block_lines: list[str] = []
                cursor = index + 1
                while cursor < len(lines):
                    candidate = lines[cursor]
                    candidate_stripped = candidate.strip()
                    if candidate_stripped and _leading_spaces(candidate) <= run_indent:
                        break
                    block_lines.append(candidate)
                    cursor += 1
                commands = _logical_shell_commands(block_lines, path, step_name)
                blocks.append((step_name, commands))
                index = cursor
                continue
            if suffix.startswith("|") or suffix.startswith(">") or not suffix:
                raise DependencyContractError(
                    f"{path} step {step_name!r} must use run: | or a single literal command"
                )
            for probe in range(index + 1, len(lines)):
                probe_line = lines[probe]
                if not probe_line.strip():
                    continue
                if _leading_spaces(probe_line) > indent:
                    raise DependencyContractError(
                        f"{path} step {step_name!r} must not use a multi-line plain run scalar"
                    )
                break
            blocks.append((step_name, (suffix,)))

        index += 1

    return tuple(blocks)


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


def _require_restricted_non_install_run_blocks(text: str, path: Path) -> None:
    for step_name, commands in _extract_run_blocks(text, path):
        if step_name == INSTALL_STEP_NAME:
            continue
        for command in commands:
            if any(marker in command for marker in ("$(", "`", "<(", ">(")):
                raise DependencyContractError(
                    f"{path} step {step_name!r} uses forbidden command indirection: {command}"
                )
            try:
                tokens = shlex.split(command, comments=True, posix=True)
            except ValueError as exc:
                raise DependencyContractError(
                    f"{path} step {step_name!r} contains an unparsable command: {command}"
                ) from exc
            if not tokens:
                continue
            if any(token in SHELL_CONTROL_TOKENS for token in tokens):
                raise DependencyContractError(
                    f"{path} step {step_name!r} must not chain or pipe commands: {command}"
                )
            if any(SHELL_ASSIGNMENT_RE.fullmatch(token) for token in tokens):
                raise DependencyContractError(
                    f"{path} step {step_name!r} must not construct commands through shell assignments: {command}"
                )
            if tokens[0] != "python":
                raise DependencyContractError(
                    f"{path} step {step_name!r} command is outside the restricted Python grammar: {command}"
                )
            if len(tokens) < 2:
                raise DependencyContractError(
                    f"{path} step {step_name!r} contains a bare python command"
                )

            target = tokens[1]
            if target == "-m":
                if len(tokens) < 3 or tokens[2] not in ALLOWED_PYTHON_MODULES:
                    raise DependencyContractError(
                        f"{path} step {step_name!r} uses an unapproved Python module target: {command}"
                    )
            elif target == "-":
                if len(tokens) < 3 or not tokens[2].startswith("<<"):
                    raise DependencyContractError(
                        f"{path} step {step_name!r} uses unsupported stdin execution: {command}"
                    )
            elif target not in ALLOWED_PYTHON_SCRIPTS:
                raise DependencyContractError(
                    f"{path} step {step_name!r} uses an unapproved Python script target: {command}"
                )


def _require_hash_enforced_workflow(path: Path) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    install_commands = _extract_install_step_commands(text, path)
    if install_commands != CANONICAL_INSTALL_COMMANDS:
        raise DependencyContractError(
            f"{path} {INSTALL_STEP_NAME!r} commands must exactly match the protected install contract"
        )
    _require_restricted_non_install_run_blocks(text, path)


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
