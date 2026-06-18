#!/usr/bin/env python3
"""Run the experimental Causal Equilibrium conformance fixture set.

The runner is intentionally dependency-light and produces deterministic JSON
and Markdown reports. It does not mutate the fixture contract or evaluator
state, and it makes no claim about decision correctness, safety, or policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cml.experimental.equilibrium import (  # noqa: E402
    CausalEquilibriumSnapshot,
    EquilibriumState,
    evaluate_causal_equilibrium,
)

REPORT_SCHEMA_VERSION = "cml-equilibrium-report-v1"
FIXTURE_SCHEMA_VERSION = "cml-equilibrium-fixtures-v1"
FINDINGS_ORDER = (
    "code_asc,severity_fail_before_warn,refs_lexicographic_asc,message_asc"
)
SEVERITY_RANK = {"FAIL": 0, "WARN": 1}
SNAPSHOT_LIST_FIELDS = (
    "supporting_refs",
    "counter_refs",
    "recalled_memory_refs",
    "unresolved_refs",
    "consolidation_source_refs",
    "consolidation_preserved_refs",
)
SNAPSHOT_REQUIRED_FIELDS = (
    "action_ref",
    *SNAPSHOT_LIST_FIELDS,
    "require_counterevidence",
    "metadata",
)
FIXTURE_REQUIRED_FIELDS = (
    "fixture_id",
    "schema_version",
    "findings_order",
    "description",
    "snapshot",
    "known_refs",
    "expected_state",
    "expected_findings",
)


class BenchmarkInputError(ValueError):
    """Raised when a fixture contract is malformed or unsupported."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BenchmarkInputError(message)


def _is_non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _validate_string_list(
    value: object,
    *,
    field_name: str,
    require_sorted: bool = False,
) -> list[str]:
    _require(isinstance(value, list), f"{field_name} must be a list")
    _require(
        all(_is_non_empty_string(item) for item in value),
        f"{field_name} must contain non-empty strings",
    )
    typed = list(value)
    _require(
        len(typed) == len(set(typed)),
        f"{field_name} must not contain duplicates",
    )
    if require_sorted:
        _require(typed == sorted(typed), f"{field_name} must be sorted")
    return typed


def _finding_sort_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding["code"],
        SEVERITY_RANK[finding["severity"]],
        tuple(finding["refs"]),
        finding["message"],
    )


def _validate_finding(
    finding: object,
    *,
    fixture_id: str,
    index: int,
) -> dict[str, Any]:
    prefix = f"fixture {fixture_id} expected_findings[{index}]"
    _require(isinstance(finding, dict), f"{prefix} must be an object")
    _require(
        set(finding) == {"code", "severity", "message", "refs"},
        f"{prefix} must contain exactly code, severity, message, refs",
    )
    _require(_is_non_empty_string(finding["code"]), f"{prefix}.code is invalid")
    _require(
        finding["severity"] in SEVERITY_RANK,
        f"{prefix}.severity must be FAIL or WARN",
    )
    _require(
        _is_non_empty_string(finding["message"]),
        f"{prefix}.message is invalid",
    )
    _validate_string_list(
        finding["refs"],
        field_name=f"{prefix}.refs",
        require_sorted=True,
    )
    return dict(finding)


def _validate_snapshot(snapshot: object, *, fixture_id: str) -> dict[str, Any]:
    prefix = f"fixture {fixture_id} snapshot"
    _require(isinstance(snapshot, dict), f"{prefix} must be an object")
    _require(
        set(snapshot) == set(SNAPSHOT_REQUIRED_FIELDS),
        f"{prefix} must contain exactly the v1 snapshot fields",
    )
    _require(
        _is_non_empty_string(snapshot["action_ref"]),
        f"{prefix}.action_ref is invalid",
    )
    for field_name in SNAPSHOT_LIST_FIELDS:
        _validate_string_list(
            snapshot[field_name],
            field_name=f"{prefix}.{field_name}",
        )
    _require(
        isinstance(snapshot["require_counterevidence"], bool),
        f"{prefix}.require_counterevidence must be boolean",
    )
    _require(isinstance(snapshot["metadata"], dict), f"{prefix}.metadata must be an object")
    return dict(snapshot)


def load_contract(path: Path) -> dict[str, Any]:
    """Load and validate one v1 fixture contract."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BenchmarkInputError(f"invalid JSON in {path}: {exc.msg}") from exc
    except OSError as exc:
        raise BenchmarkInputError(f"cannot read fixture file {path}: {exc}") from exc

    _require(isinstance(raw, dict), "fixture contract must be a JSON object")
    _require(
        raw.get("contract_id") == "cml-causal-equilibrium-conformance-v1",
        "unsupported or missing contract_id",
    )
    _require(
        raw.get("schema_version") == FIXTURE_SCHEMA_VERSION,
        "unsupported or missing schema_version",
    )
    _require(
        raw.get("findings_order") == FINDINGS_ORDER,
        "unsupported or missing findings_order",
    )
    fixtures = raw.get("fixtures")
    _require(isinstance(fixtures, list) and fixtures, "fixtures must be a non-empty list")

    validated: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, fixture in enumerate(fixtures):
        _require(isinstance(fixture, dict), f"fixtures[{index}] must be an object")
        _require(
            set(fixture) == set(FIXTURE_REQUIRED_FIELDS),
            f"fixtures[{index}] must contain exactly the v1 fixture fields",
        )
        fixture_id = fixture["fixture_id"]
        _require(_is_non_empty_string(fixture_id), f"fixtures[{index}].fixture_id is invalid")
        _require(fixture_id not in seen_ids, f"duplicate fixture_id: {fixture_id}")
        seen_ids.add(fixture_id)
        _require(
            fixture["schema_version"] == FIXTURE_SCHEMA_VERSION,
            f"fixture {fixture_id} has unsupported schema_version",
        )
        _require(
            fixture["findings_order"] == FINDINGS_ORDER,
            f"fixture {fixture_id} has unsupported findings_order",
        )
        _require(
            _is_non_empty_string(fixture["description"]),
            f"fixture {fixture_id} description is invalid",
        )
        snapshot = _validate_snapshot(fixture["snapshot"], fixture_id=fixture_id)
        known_refs = _validate_string_list(
            fixture["known_refs"],
            field_name=f"fixture {fixture_id} known_refs",
            require_sorted=True,
        )
        _require(
            fixture["expected_state"] in {state.value for state in EquilibriumState},
            f"fixture {fixture_id} expected_state is invalid",
        )
        expected_raw = fixture["expected_findings"]
        _require(
            isinstance(expected_raw, list),
            f"fixture {fixture_id} expected_findings must be a list",
        )
        expected_findings = [
            _validate_finding(item, fixture_id=fixture_id, index=item_index)
            for item_index, item in enumerate(expected_raw)
        ]
        _require(
            expected_findings == sorted(expected_findings, key=_finding_sort_key),
            f"fixture {fixture_id} expected_findings are not in canonical order",
        )
        validated.append(
            {
                "fixture_id": fixture_id,
                "schema_version": fixture["schema_version"],
                "findings_order": fixture["findings_order"],
                "description": fixture["description"],
                "snapshot": snapshot,
                "known_refs": known_refs,
                "expected_state": fixture["expected_state"],
                "expected_findings": expected_findings,
            }
        )

    return {
        "contract_id": raw["contract_id"],
        "schema_version": raw["schema_version"],
        "findings_order": raw["findings_order"],
        "fixtures": sorted(validated, key=lambda item: item["fixture_id"]),
    }


def _to_snapshot(raw: dict[str, Any]) -> CausalEquilibriumSnapshot:
    return CausalEquilibriumSnapshot(
        action_ref=raw["action_ref"],
        supporting_refs=tuple(raw["supporting_refs"]),
        counter_refs=tuple(raw["counter_refs"]),
        recalled_memory_refs=tuple(raw["recalled_memory_refs"]),
        unresolved_refs=tuple(raw["unresolved_refs"]),
        consolidation_source_refs=tuple(raw["consolidation_source_refs"]),
        consolidation_preserved_refs=tuple(raw["consolidation_preserved_refs"]),
        require_counterevidence=raw["require_counterevidence"],
        metadata=dict(raw["metadata"]),
    )


def _serialize_findings(findings: Iterable[Any]) -> list[dict[str, Any]]:
    return [
        {
            "code": finding.code,
            "severity": finding.severity.value,
            "message": finding.message,
            "refs": list(finding.refs),
        }
        for finding in findings
    ]


def evaluate_fixture(fixture: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one validated fixture and compare actual vs expected output."""

    result = evaluate_causal_equilibrium(
        _to_snapshot(fixture["snapshot"]),
        known_refs=fixture["known_refs"],
    )
    actual_findings = _serialize_findings(result.findings)
    passed = (
        result.state.value == fixture["expected_state"]
        and actual_findings == fixture["expected_findings"]
    )
    return {
        "fixture_id": fixture["fixture_id"],
        "description": fixture["description"],
        "expected_state": fixture["expected_state"],
        "actual_state": result.state.value,
        "expected_findings": fixture["expected_findings"],
        "actual_findings": actual_findings,
        "passed": passed,
    }


def run_benchmark(
    contract: dict[str, Any],
    *,
    implementation_commit: str,
) -> dict[str, Any]:
    """Evaluate all fixtures and return a deterministic report object."""

    _require(_is_non_empty_string(implementation_commit), "implementation_commit is invalid")
    fixture_results = [evaluate_fixture(fixture) for fixture in contract["fixtures"]]
    fixture_results.sort(key=lambda item: item["fixture_id"])

    passed_count = sum(1 for item in fixture_results if item["passed"])
    state_counts = Counter(item["actual_state"] for item in fixture_results)
    finding_counts = Counter(
        finding["code"]
        for item in fixture_results
        for finding in item["actual_findings"]
    )

    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "contract_id": contract["contract_id"],
        "fixture_schema_version": contract["schema_version"],
        "findings_order": contract["findings_order"],
        "implementation_commit": implementation_commit,
        "total": len(fixture_results),
        "passed": passed_count,
        "failed": len(fixture_results) - passed_count,
        "state_counts": {
            state.value: state_counts.get(state.value, 0)
            for state in EquilibriumState
        },
        "finding_code_counts": dict(sorted(finding_counts.items())),
        "fixtures": fixture_results,
    }


def json_report_text(report: dict[str, Any]) -> str:
    """Serialize a report with stable key ordering and a trailing newline."""

    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _finding_summary(findings: Sequence[dict[str, Any]]) -> str:
    if not findings:
        return "—"
    parts: list[str] = []
    for finding in findings:
        refs = ",".join(finding["refs"])
        suffix = f"[{refs}]" if refs else ""
        parts.append(f"{finding['code']}:{finding['severity']}{suffix}")
    return "; ".join(parts)


def _escape_markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def markdown_report_text(report: dict[str, Any]) -> str:
    """Render a deterministic reviewer-friendly Markdown report."""

    overall = "PASS" if report["failed"] == 0 else "FAIL"
    lines = [
        "# Causal Equilibrium Benchmark Report",
        "",
        f"- **Result:** `{overall}`",
        f"- **Contract:** `{report['contract_id']}`",
        f"- **Fixture schema:** `{report['fixture_schema_version']}`",
        f"- **Report schema:** `{report['report_schema_version']}`",
        f"- **Implementation commit:** `{report['implementation_commit']}`",
        f"- **Total / passed / failed:** `{report['total']} / {report['passed']} / {report['failed']}`",
        "",
        "## Fixture results",
        "",
        "| Fixture | Expected | Actual | Actual findings | Result |",
        "|---|---|---|---|---|",
    ]
    for fixture in report["fixtures"]:
        result = "PASS" if fixture["passed"] else "FAIL"
        lines.append(
            "| {fixture_id} | {expected} | {actual} | {findings} | {result} |".format(
                fixture_id=_escape_markdown_cell(fixture["fixture_id"]),
                expected=_escape_markdown_cell(fixture["expected_state"]),
                actual=_escape_markdown_cell(fixture["actual_state"]),
                findings=_escape_markdown_cell(
                    _finding_summary(fixture["actual_findings"])
                ),
                result=result,
            )
        )

    failed = [fixture for fixture in report["fixtures"] if not fixture["passed"]]
    if failed:
        lines.extend(["", "## Mismatches", ""])
        for fixture in failed:
            lines.extend(
                [
                    f"### `{fixture['fixture_id']}`",
                    "",
                    "**Expected**",
                    "",
                    "```json",
                    json.dumps(
                        {
                            "state": fixture["expected_state"],
                            "findings": fixture["expected_findings"],
                        },
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    ),
                    "```",
                    "",
                    "**Actual**",
                    "",
                    "```json",
                    json.dumps(
                        {
                            "state": fixture["actual_state"],
                            "findings": fixture["actual_findings"],
                        },
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    ),
                    "```",
                    "",
                ]
            )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A PASS means the implementation reproduced the published experimental fixture expectations exactly. It does not prove decision correctness, safety, fairness, compliance, or truth.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def resolve_implementation_commit(explicit: str | None = None) -> str:
    """Resolve the commit identifier recorded in a report."""

    if explicit:
        return explicit
    from_environment = os.environ.get("CML_IMPLEMENTATION_COMMIT")
    if from_environment:
        return from_environment
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    commit = completed.stdout.strip()
    return commit or "unknown"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Causal Equilibrium conformance fixtures."
    )
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--markdown-out", type=Path, required=True)
    parser.add_argument(
        "--implementation-commit",
        help="Commit identifier for the report; defaults to git rev-parse HEAD.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        contract = load_contract(args.fixtures)
        report = run_benchmark(
            contract,
            implementation_commit=resolve_implementation_commit(
                args.implementation_commit
            ),
        )
        json_text = json_report_text(report)
        markdown_text = markdown_report_text(report)
        _write_text(args.json_out, json_text)
        _write_text(args.markdown_out, markdown_text)
    except (BenchmarkInputError, TypeError, ValueError) as exc:
        print(f"Causal Equilibrium benchmark input error: {exc}", file=sys.stderr)
        return 2

    digest = hashlib.sha256(json_text.encode("utf-8")).hexdigest()
    print(
        "Causal Equilibrium benchmark: "
        f"{report['passed']}/{report['total']} passed; "
        f"JSON SHA-256: {digest}"
    )
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
