from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .cause_band_trajectory import is_oscillating, recovered_to_safe, trajectory_direction

BAND_RANK = {
    "safe_range": 0,
    "warning_range": 1,
    "danger_range": 2,
    "critical_range": 3,
}

RANGE_DRIFT = "CML-AUDIT-RANGE-DRIFT"
PERSISTENT_DEVIATION = "CML-AUDIT-RANGE-PERSISTENT_DEVIATION"
CRITICAL_EXIT = "CML-AUDIT-RANGE-CRITICAL_EXIT"

DEFAULT_FIXTURE = Path("benchmarks/experimental/07_range_drift_intent.json")


def resolve_fixture_path(path: Path) -> Path:
    base_dir = DEFAULT_FIXTURE.parent.resolve()
    if path.is_absolute():
        raise SystemExit(f"Fixture path not allowed: {path}")
    if any(part == ".." for part in path.parts):
        raise SystemExit(f"Fixture path not allowed: {path}")
    candidate = base_dir / path
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(base_dir)
    except ValueError as exc:
        raise SystemExit(f"Fixture path not allowed: {path}") from exc
    return resolved


def parse_duration_threshold(raw: Any, default: int = 3) -> int:
    if isinstance(raw, int) and raw > 0:
        return raw
    if isinstance(raw, str):
        match = re.match(r"\s*(\d+)", raw)
        if match:
            value = int(match.group(1))
            if value > 0:
                return value
    return default


def load_fixture(path: Path) -> dict[str, Any]:
    safe_path = resolve_fixture_path(path)
    try:
        raw = json.loads(safe_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"Fixture not found: {safe_path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {safe_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise SystemExit(f"Fixture must be a JSON object: {safe_path}")
    return raw


def max_consecutive_outside_safe(ranks: list[int]) -> int:
    current = 0
    best = 0
    for rank in ranks:
        if rank > BAND_RANK["safe_range"]:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def evaluate_fixture(raw: dict[str, Any]) -> dict[str, Any]:
    trajectory = raw.get("trajectory")
    if not isinstance(trajectory, list) or not trajectory:
        raise SystemExit("Fixture must contain a non-empty trajectory list")

    bands: list[str] = []
    ranks: list[int] = []
    invalid_bands: list[str] = []

    for step in trajectory:
        if not isinstance(step, dict):
            raise SystemExit("Each trajectory step must be an object")
        band = step.get("band")
        if not isinstance(band, str):
            raise SystemExit("Each trajectory step must contain a string band")
        bands.append(band)
        if band not in BAND_RANK:
            invalid_bands.append(band)
            continue
        ranks.append(BAND_RANK[band])

    if invalid_bands:
        raise SystemExit(f"Unknown Cause Band values: {sorted(set(invalid_bands))}")

    policy = raw.get("cause_band_policy") if isinstance(raw.get("cause_band_policy"), dict) else {}
    duration_threshold = parse_duration_threshold(policy.get("duration_threshold"), default=3)

    findings: list[str] = []
    if any(rank >= BAND_RANK["warning_range"] for rank in ranks):
        findings.append(RANGE_DRIFT)

    max_consecutive = max_consecutive_outside_safe(ranks)
    if max_consecutive >= duration_threshold:
        findings.append(PERSISTENT_DEVIATION)

    if any(rank >= BAND_RANK["critical_range"] for rank in ranks):
        findings.append(CRITICAL_EXIT)

    expected_future = raw.get("expected_future_cause_band_behavior")
    expected_codes: list[str] = []
    if isinstance(expected_future, dict) and isinstance(expected_future.get("expected_codes"), list):
        expected_codes = sorted(str(code) for code in expected_future["expected_codes"])

    predicted_codes = sorted(findings)
    return {
        "case_id": raw.get("case_id"),
        "status": raw.get("status", "experimental"),
        "duration_threshold": duration_threshold,
        "bands": bands,
        "trajectory_direction": trajectory_direction(ranks),
        "recovered_to_safe": recovered_to_safe(ranks),
        "oscillating": is_oscillating(ranks),
        "max_consecutive_outside_safe": max_consecutive,
        "predicted_codes": predicted_codes,
        "expected_future_codes": expected_codes,
        "matches_expected_future": predicted_codes == expected_codes if expected_codes else None,
    }


def render_text(result: dict[str, Any]) -> str:
    expected = result["expected_future_codes"] or ["<none>"]
    lines = [
        "Experimental Cause Band evaluation",
        f"case_id={result['case_id']}",
        f"status={result['status']}",
        f"duration_threshold={result['duration_threshold']}",
        f"bands={' -> '.join(result['bands'])}",
        f"trajectory_direction={result['trajectory_direction']}",
        f"recovered_to_safe={result['recovered_to_safe']}",
        f"oscillating={result['oscillating']}",
        f"max_consecutive_outside_safe={result['max_consecutive_outside_safe']}",
        f"predicted_codes={','.join(result['predicted_codes']) or '-'}",
        f"expected_future_codes={','.join(expected)}",
    ]
    if result["matches_expected_future"] is not None:
        lines.append(f"matches_expected_future={result['matches_expected_future']}")
    return "\n".join(lines)
