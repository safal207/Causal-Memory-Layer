from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .audit import AuditConfig, AuditEngine
from .record import CausalRecord


@dataclass
class SafetyEvalCase:
    case_id: str
    description: str
    expected_passed: bool
    expected_codes: list[str]
    records: list[CausalRecord]
    config: AuditConfig = field(default_factory=AuditConfig)


@dataclass
class SafetyEvalResult:
    case_id: str
    description: str
    expected_passed: bool
    predicted_passed: bool
    expected_codes: list[str]
    predicted_codes: list[str]
    matched: bool


@dataclass
class SafetyEvalSummary:
    total_cases: int
    matched_cases: int
    mismatches: int
    expected_passed: int
    expected_failed: int
    predicted_passed: int
    predicted_failed: int


_ALLOWED_KEYS = {"case_id", "description", "expected_passed", "expected_codes", "records", "config"}


def _config_from_raw(raw: dict | None) -> AuditConfig:
    if raw is None:
        return AuditConfig()
    if not isinstance(raw, dict):
        raise ValueError("config must be an object")
    return AuditConfig._apply_raw(AuditConfig(), raw)


def load_safety_eval_cases(fixtures_root: Path) -> list[SafetyEvalCase]:
    fixtures_root = Path(fixtures_root)
    if not fixtures_root.exists():
        raise FileNotFoundError(f"Fixtures directory not found: {fixtures_root}")

    cases: list[SafetyEvalCase] = []
    seen: set[str] = set()
    for path in sorted(fixtures_root.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"{path} must contain a JSON object")
        unknown = set(raw) - _ALLOWED_KEYS
        if unknown:
            raise ValueError(f"{path} contains unsupported keys: {sorted(unknown)}")

        case_id = raw.get("case_id")
        description = raw.get("description")
        expected_passed = raw.get("expected_passed")
        expected_codes = raw.get("expected_codes")
        records = raw.get("records")

        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"{path} is missing a valid case_id")
        if case_id in seen:
            raise ValueError(f"Duplicate case_id: {case_id}")
        seen.add(case_id)
        if not isinstance(description, str) or not description.strip():
            raise ValueError(f"{path} is missing a valid description")
        if not isinstance(expected_passed, bool):
            raise ValueError(f"{path} is missing a boolean expected_passed")
        if not isinstance(expected_codes, list) or any(not isinstance(code, str) for code in expected_codes):
            raise ValueError(f"{path} must define expected_codes as a list of strings")
        if not isinstance(records, list) or not records:
            raise ValueError(f"{path} must define a non-empty records list")

        cases.append(
            SafetyEvalCase(
                case_id=case_id,
                description=description,
                expected_passed=expected_passed,
                expected_codes=sorted(expected_codes),
                records=[CausalRecord.from_dict(item) for item in records],
                config=_config_from_raw(raw.get("config")),
            )
        )
    return cases


def run_safety_eval(fixtures_root: Path) -> tuple[list[SafetyEvalResult], SafetyEvalSummary]:
    cases = load_safety_eval_cases(fixtures_root)
    results: list[SafetyEvalResult] = []

    expected_passed = 0
    predicted_passed = 0
    matched_cases = 0

    for case in cases:
        audit_result = AuditEngine(case.config).run(case.records)
        predicted_codes = sorted(f.code for f in audit_result.findings)
        predicted_ok = audit_result.passed()
        matched = predicted_ok == case.expected_passed and predicted_codes == case.expected_codes
        if case.expected_passed:
            expected_passed += 1
        if predicted_ok:
            predicted_passed += 1
        if matched:
            matched_cases += 1
        results.append(
            SafetyEvalResult(
                case_id=case.case_id,
                description=case.description,
                expected_passed=case.expected_passed,
                predicted_passed=predicted_ok,
                expected_codes=case.expected_codes,
                predicted_codes=predicted_codes,
                matched=matched,
            )
        )

    total_cases = len(cases)
    return results, SafetyEvalSummary(
        total_cases=total_cases,
        matched_cases=matched_cases,
        mismatches=total_cases - matched_cases,
        expected_passed=expected_passed,
        expected_failed=total_cases - expected_passed,
        predicted_passed=predicted_passed,
        predicted_failed=total_cases - predicted_passed,
    )


def render_text_report(results: list[SafetyEvalResult], summary: SafetyEvalSummary) -> str:
    lines = [
        "CML safety-eval benchmark",
        f"total_cases={summary.total_cases} matched={summary.matched_cases} mismatches={summary.mismatches}",
        f"expected_passed={summary.expected_passed} expected_failed={summary.expected_failed}",
        f"predicted_passed={summary.predicted_passed} predicted_failed={summary.predicted_failed}",
        "",
    ]
    for result in results:
        status = "PASS" if result.matched else "FAIL"
        lines.append(
            f"- {result.case_id}: {status} expected_passed={result.expected_passed} predicted_passed={result.predicted_passed} expected_codes={','.join(result.expected_codes) or '-'} predicted_codes={','.join(result.predicted_codes) or '-'}"
        )
    return "\n".join(lines)


def render_markdown_report(results: list[SafetyEvalResult], summary: SafetyEvalSummary) -> str:
    lines = [
        "# CML Safety-Eval Results",
        "",
        "Deterministic benchmark report generated from `benchmarks/fixtures`.",
        "",
        "## Summary",
        "",
        f"- Total cases: **{summary.total_cases}**",
        f"- Matched cases: **{summary.matched_cases}**",
        f"- Mismatches: **{summary.mismatches}**",
        f"- Expected passed / failed: **{summary.expected_passed} / {summary.expected_failed}**",
        f"- Predicted passed / failed: **{summary.predicted_passed} / {summary.predicted_failed}**",
        "",
        "## Per-case results",
        "",
        "| case_id | expected | predicted | status | expected_codes | predicted_codes |",
        "|---|---|---|---|---|---|",
    ]
    for result in results:
        expected = "pass" if result.expected_passed else "fail"
        predicted = "pass" if result.predicted_passed else "fail"
        status = "PASS" if result.matched else "FAIL"
        expected_codes = "<none>" if not result.expected_codes else ", ".join(result.expected_codes)
        predicted_codes = "<none>" if not result.predicted_codes else ", ".join(result.predicted_codes)
        lines.append(
            f"| {result.case_id} | {expected} | {predicted} | {status} | {expected_codes} | {predicted_codes} |"
        )
    return "\n".join(lines) + "\n"
