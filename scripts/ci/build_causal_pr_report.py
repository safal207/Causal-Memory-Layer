#!/usr/bin/env python3
"""Build and enforce a causal transition contract for pull requests."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from scripts.ci.assert_exact_head import write_json_atomic

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEADING_RE = re.compile(r"(?m)^#{2,4}\s+(.+?)\s*$")
PLACEHOLDER_RE = re.compile(
    r"(?im)(?:^\s*(?:todo|tbd|placeholder|describe)\b|<[^>\n]+>)"
)
URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(
    r"(?i)\b(password|secret|token|api[_ -]?key)\s*[:=]\s*\S+"
)
TEST_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"((?:tests|hackathons/[^/\s]+/tests)/[A-Za-z0-9_./-]+\."
    r"(?:py|pyi|js|jsx|mjs|cjs|ts|tsx|go|rs|java|kt|kts|rb|php|swift|scala|c|cc|cpp|cs|sh))"
)

SECTION_ALIASES = {
    "failure_path": {"failure path", "failure mode"},
    "invariant": {"invariant after change", "target invariant", "invariant"},
    "regression_evidence": {
        "regression evidence",
        "regression test",
        "verification evidence",
    },
    "residual_risk": {"residual risk", "remaining risk"},
}

IMPLEMENTATION_ROOTS = (
    "api/",
    "app/",
    "apps/",
    "cli/",
    "client/",
    "cml/",
    "deploy/",
    "deployment/",
    "docker/",
    "hackathons/",
    "infra/",
    "infrastructure/",
    "integrations/",
    "packages/",
    "scripts/",
    "server/",
    "services/",
    "src/",
    "web/",
    ".github/actions/",
    ".github/trust-root/",
)
IMPLEMENTATION_SUFFIXES = {
    ".bash",
    ".bat",
    ".c",
    ".cc",
    ".cfg",
    ".cjs",
    ".cmd",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".cxx",
    ".env",
    ".fish",
    ".go",
    ".gql",
    ".gradle",
    ".graphql",
    ".h",
    ".hcl",
    ".hpp",
    ".html",
    ".ini",
    ".ipynb",
    ".java",
    ".js",
    ".json",
    ".jsonc",
    ".jsx",
    ".kt",
    ".kts",
    ".less",
    ".lock",
    ".lua",
    ".mjs",
    ".php",
    ".properties",
    ".proto",
    ".ps1",
    ".py",
    ".pyi",
    ".r",
    ".rb",
    ".rs",
    ".sass",
    ".scala",
    ".scss",
    ".sh",
    ".sql",
    ".svelte",
    ".swift",
    ".tf",
    ".tfvars",
    ".toml",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}
IMPLEMENTATION_FILENAMES = {
    "build.gradle",
    "build.gradle.kts",
    "cargo.lock",
    "cargo.toml",
    "composer.json",
    "composer.lock",
    "containerfile",
    "dockerfile",
    "gemfile",
    "gemfile.lock",
    "gnumakefile",
    "go.mod",
    "go.sum",
    "gradlew",
    "gradlew.bat",
    "justfile",
    "makefile",
    "package-lock.json",
    "package.json",
    "pipfile",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "procfile",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "terraform.lock.hcl",
    "tox.ini",
    "uv.lock",
    "yarn.lock",
}
DOCUMENTATION_SUFFIXES = {".adoc", ".md", ".mdx", ".rst"}
DOCUMENTATION_MEDIA_SUFFIXES = {
    ".gif",
    ".jpeg",
    ".jpg",
    ".pdf",
    ".png",
    ".svg",
    ".webp",
}
DOCUMENTATION_NAME_PREFIXES = (
    "authors",
    "changelog",
    "code_of_conduct",
    "contributing",
    "license",
    "notice",
    "readme",
)
WORKFLOW_CONTRACT_PATHS = {
    "tests/test_ci_workflow_contract.py",
    "tests/test_causal_pr_contract.py",
}


@dataclass(frozen=True)
class Change:
    """One normalized path transition from the pull-request diff."""

    status: str
    path: str
    previous_path: str | None = None


def _run_git(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _git_is_ancestor(repo_root: Path, base_sha: str, head_sha: str) -> bool:
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base_sha, head_sha],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError(completed.stderr.strip() or "git merge-base failed")
    return completed.returncode == 0


def _normalize_heading(value: str) -> str:
    normalized = re.sub(r"[`*_\[\]():]", " ", value).casefold()
    return " ".join(normalized.split())


def _extract_sections(body: str) -> tuple[dict[str, str], set[str]]:
    """Extract causal sections while preserving the first canonical occurrence."""

    matches = list(HEADING_RE.finditer(body or ""))
    sections: dict[str, str] = {}
    duplicates: set[str] = set()
    for index, match in enumerate(matches):
        heading = _normalize_heading(match.group(1))
        canonical = next(
            (
                name
                for name, aliases in SECTION_ALIASES.items()
                if heading in aliases
            ),
            None,
        )
        if canonical is None:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        if canonical in sections:
            duplicates.add(canonical)
            continue
        sections[canonical] = body[match.end() : end].strip()
    return sections, duplicates


def extract_sections(body: str) -> dict[str, str]:
    """Extract unique required causal-review sections from Markdown PR text."""

    sections, _ = _extract_sections(body)
    return sections


def _is_test_path(path: str) -> bool:
    normalized = path.casefold()
    name = Path(normalized).name
    return (
        normalized.startswith("tests/")
        or "/tests/" in normalized
        or normalized.startswith("__tests__/")
        or "/__tests__/" in normalized
        or name.startswith("test_")
        or ".test." in name
        or ".spec." in name
    )


def _has_runtime_identity(path: str) -> bool:
    normalized = path.casefold()
    name = Path(normalized).name
    suffix = Path(normalized).suffix
    return (
        name in IMPLEMENTATION_FILENAMES
        or name.startswith("requirements")
        or suffix in IMPLEMENTATION_SUFFIXES
    )


def _is_documentation_path(path: str) -> bool:
    normalized = path.casefold()
    name = Path(normalized).name
    suffix = Path(normalized).suffix
    if _has_runtime_identity(normalized):
        return False
    if suffix in DOCUMENTATION_SUFFIXES:
        return True
    if suffix == "" and name.startswith(DOCUMENTATION_NAME_PREFIXES):
        return True
    return normalized.startswith("docs/") and suffix in DOCUMENTATION_MEDIA_SUFFIXES


def _is_workflow_contract_change(path: str) -> bool:
    normalized = path.casefold()
    return normalized.startswith(".github/workflows/") or normalized == (
        "scripts/ci/verify_workflow_contract.py"
    )


def _is_implementation_path(path: str) -> bool:
    normalized = path.casefold()
    if _is_test_path(normalized) or _is_workflow_contract_change(normalized):
        return False
    if _has_runtime_identity(normalized):
        return True
    if _is_documentation_path(normalized):
        return False
    return normalized.startswith(IMPLEMENTATION_ROOTS)


def _all_change_paths(changes: Iterable[Change]) -> list[str]:
    return sorted(
        {
            path
            for change in changes
            for path in (change.path, change.previous_path)
            if path
        }
    )


def classify_changes(changes: Iterable[Change]) -> dict[str, list[str]]:
    """Classify both sides of every path transition into causal domains."""

    paths = _all_change_paths(changes)
    return {
        "implementation": [path for path in paths if _is_implementation_path(path)],
        "tests": [path for path in paths if _is_test_path(path)],
        "workflows": [path for path in paths if _is_workflow_contract_change(path)],
        "documentation": [path for path in paths if _is_documentation_path(path)],
        "other": [
            path
            for path in paths
            if not (
                _is_implementation_path(path)
                or _is_test_path(path)
                or _is_workflow_contract_change(path)
                or _is_documentation_path(path)
            )
        ],
    }


def changed_files(repo_root: Path, base_sha: str, head_sha: str) -> list[Change]:
    """Read a direct, rename-aware exact-base-to-head diff."""

    output = _run_git(
        repo_root,
        "diff",
        "--name-status",
        "--find-renames",
        base_sha,
        head_sha,
        "--",
    )
    changes: list[Change] = []
    for line in output.splitlines():
        if not line:
            continue
        parts = line.split("\t")
        status = parts[0]
        if status.startswith(("R", "C")) and len(parts) == 3:
            changes.append(Change(status=status, path=parts[2], previous_path=parts[1]))
        elif len(parts) == 2:
            changes.append(Change(status=status, path=parts[1]))
        else:
            raise ValueError("git diff returned an unsupported name-status record")
    return changes


def _safe_summary(value: str, limit: int = 180) -> str:
    sanitized = URL_RE.sub("[URL]", value)
    sanitized = SECRET_VALUE_RE.sub(
        lambda match: f"{match.group(1)}=[REDACTED]", sanitized
    )
    sanitized = " ".join(sanitized.split())
    if len(sanitized) > limit:
        return sanitized[: limit - 1] + "…"
    return sanitized


def _contains_placeholder(value: str) -> bool:
    normalized = " ".join(value.split()).casefold()
    return bool(PLACEHOLDER_RE.search(value)) or normalized in {"n/a", "na", "none"}


def _section_metadata(sections: dict[str, str]) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "present": bool(value.strip()),
            "characters": len(value.strip()),
            "sha256": hashlib.sha256(value.strip().encode("utf-8")).hexdigest(),
            "summary": _safe_summary(value),
        }
        for name, value in sections.items()
    }


def _existing_test_references(section: str, repo_root: Path) -> list[str]:
    root = repo_root.resolve()
    existing: list[str] = []
    for path in sorted(set(TEST_PATH_RE.findall(section))):
        candidate = (root / path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if candidate.is_file():
            existing.append(path)
    return existing


def evaluate_transition(
    *,
    repo_root: Path,
    base_sha: str,
    head_sha: str,
    changes: list[Change],
    body: str,
    current_head: str,
    dirty: bool,
    base_is_ancestor: bool = True,
) -> dict[str, Any]:
    """Evaluate one PR state transition without calling GitHub APIs."""

    violations: list[str] = []
    if not SHA_RE.fullmatch(base_sha):
        violations.append("base SHA must be a full lowercase 40-character SHA")
    if not SHA_RE.fullmatch(head_sha):
        violations.append("head SHA must be a full lowercase 40-character SHA")
    if current_head != head_sha:
        violations.append("checked-out HEAD does not match the reviewed PR head")
    if dirty:
        violations.append("causal analysis requires a clean worktree")
    if not base_is_ancestor:
        violations.append("reviewed base SHA is not an ancestor of the PR head")

    groups = classify_changes(changes)
    sections, duplicate_sections = _extract_sections(body)
    for name in sorted(duplicate_sections):
        violations.append(f"duplicate causal review section: {name}")
    strict = bool(
        groups["implementation"]
        or groups["workflows"]
        or groups["tests"]
        or groups["other"]
    )

    if strict:
        for name in SECTION_ALIASES:
            value = sections.get(name, "").strip()
            if not value:
                violations.append(f"missing causal review section: {name}")
            elif _contains_placeholder(value):
                violations.append(f"causal review section contains a placeholder: {name}")

        regression = sections.get("regression_evidence", "")
        existing_references = _existing_test_references(regression, repo_root)
        if not groups["tests"] and not existing_references:
            violations.append(
                "strict changes require changed tests or explicit existing test paths"
            )

    if groups["workflows"] and not (
        WORKFLOW_CONTRACT_PATHS & set(groups["tests"])
    ):
        violations.append(
            "workflow contract changes require a causal/workflow contract regression test"
        )

    scope = "strict" if strict else "lightweight"
    section_metadata = _section_metadata(sections)
    graph = {
        "nodes": [
            {"id": "base", "label": f"base {base_sha[:12]}"},
            {
                "id": "change",
                "label": f"{len(changes)} path transitions / {scope} policy",
            },
            {
                "id": "invariant",
                "label": section_metadata.get("invariant", {}).get(
                    "summary", "documentation-only invariant"
                ),
            },
            {
                "id": "regression",
                "label": section_metadata.get("regression_evidence", {}).get(
                    "summary", "lightweight verification"
                ),
            },
            {"id": "head", "label": f"head {head_sha[:12]}"},
        ],
        "edges": [
            ["base", "change"],
            ["change", "invariant"],
            ["invariant", "regression"],
            ["regression", "head"],
        ],
    }
    return {
        "schema_version": "cml-causal-pr-report-v1",
        "passed": not violations,
        "scope": scope,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "base_is_ancestor": base_is_ancestor,
        "change_count": len(changes),
        "classified_paths": _all_change_paths(changes),
        "changes": [
            {
                "status": change.status,
                "path": change.path,
                "previous_path": change.previous_path,
            }
            for change in changes
        ],
        "groups": groups,
        "sections": section_metadata,
        "existing_test_references": _existing_test_references(
            sections.get("regression_evidence", ""), repo_root
        ),
        "graph": graph,
        "violations": violations,
    }


def _mermaid_label(value: str) -> str:
    return value.replace('"', "'").replace("\n", "<br/>")


def render_markdown(report: dict[str, Any]) -> str:
    """Render the machine report as a reviewable causal graph artifact."""

    nodes = {node["id"]: node["label"] for node in report["graph"]["nodes"]}
    status = "PASS" if report["passed"] else "FAIL"
    lines = [
        "# Causal PR transition report",
        "",
        f"- Result: **{status}**",
        f"- Policy scope: `{report['scope']}`",
        f"- Base: `{report['base_sha']}`",
        f"- Head: `{report['head_sha']}`",
        f"- Base is ancestor: `{str(report['base_is_ancestor']).lower()}`",
        f"- Path transitions: `{report['change_count']}`",
        "",
        "```mermaid",
        "flowchart LR",
        f'    B["{_mermaid_label(nodes["base"])}"] --> D["{_mermaid_label(nodes["change"])}"]',
        f'    D --> I["{_mermaid_label(nodes["invariant"])}"]',
        f'    I --> R["{_mermaid_label(nodes["regression"])}"]',
        f'    R --> H["{_mermaid_label(nodes["head"])}"]',
        "```",
        "",
        "## Changed domains",
        "",
        "| Domain | Count |",
        "|---|---:|",
    ]
    for name, paths in report["groups"].items():
        lines.append(f"| {name} | {len(paths)} |")
    lines.extend(["", "## Violations", ""])
    if report["violations"]:
        lines.extend(f"- {violation}" for violation in report["violations"])
    else:
        lines.append("- None.")
    return "\n".join(lines) + "\n"


def _event_body(event_path: Path) -> str:
    payload = json.loads(event_path.read_text(encoding="utf-8"))
    pull_request = payload.get("pull_request")
    if not isinstance(pull_request, dict):
        return ""
    body = pull_request.get("body")
    return body if isinstance(body, str) else ""


def build_report(
    *,
    repo_root: Path,
    base_sha: str,
    head_sha: str,
    event_path: Path,
) -> dict[str, Any]:
    """Build the report from an exact checkout and a GitHub event payload."""

    for name, value in (("base", base_sha), ("head", head_sha)):
        if not SHA_RE.fullmatch(value):
            raise ValueError(
                f"{name} SHA must be a full lowercase 40-character SHA"
            )
    current_head = _run_git(repo_root, "rev-parse", "HEAD")
    dirty = bool(_run_git(repo_root, "status", "--porcelain"))
    base_is_ancestor = _git_is_ancestor(repo_root, base_sha, head_sha)
    return evaluate_transition(
        repo_root=repo_root,
        base_sha=base_sha,
        head_sha=head_sha,
        changes=changed_files(repo_root, base_sha, head_sha),
        body=_event_body(event_path),
        current_head=current_head,
        dirty=dirty,
        base_is_ancestor=base_is_ancestor,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = build_report(
        repo_root=args.repo_root.resolve(),
        base_sha=args.base,
        head_sha=args.head,
        event_path=args.event,
    )
    write_json_atomic(args.output, report)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_text(render_markdown(report), encoding="utf-8")
    if report["violations"]:
        for violation in report["violations"]:
            print(f"Causal PR contract violation: {violation}")
        raise SystemExit(1)
    print(
        "Causal PR contract verified: "
        f"{report['change_count']} transitions, {report['scope']} policy"
    )


if __name__ == "__main__":
    main()
