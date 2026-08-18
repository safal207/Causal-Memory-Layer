from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.resolve_security_evidence import (
    SecurityEvidenceError,
    resolve_security_evidence,
)

SHA = "a" * 40
RUN_ID = 123456


def _write_lane(
    root: Path,
    *,
    lane: str,
    attempt: int,
    tested_sha: str = SHA,
    passed: bool = True,
) -> Path:
    filenames = {
        "dependency": ("scanner-results.json", "cml-security-scan-results-v1"),
        "secret": ("gitleaks.json", "cml-gitleaks-result-v1"),
        "codeql": ("codeql.json", "cml-codeql-result-v1"),
    }
    filename, schema = filenames[lane]
    directory = root / f"cml-security-lane-{lane}-{RUN_ID}-{attempt}"
    directory.mkdir(parents=True)
    (directory / filename).write_text(
        json.dumps(
            {
                "schema_version": schema,
                "tested_sha": tested_sha,
                "passed": passed,
            }
        ),
        encoding="utf-8",
    )
    return directory


def test_selective_rerun_resolves_independent_latest_attempts(tmp_path: Path) -> None:
    collected = tmp_path / "collected"
    collected.mkdir()
    _write_lane(collected, lane="dependency", attempt=1)
    _write_lane(collected, lane="codeql", attempt=1)
    _write_lane(collected, lane="secret", attempt=2)

    result = resolve_security_evidence(
        collected_root=collected,
        run_id=RUN_ID,
        tested_sha=SHA,
        output_root=tmp_path / "resolved",
    )

    assert result["lanes"]["dependency"]["run_attempt"] == 1
    assert result["lanes"]["secret"]["run_attempt"] == 2
    assert result["lanes"]["codeql"]["run_attempt"] == 1
    assert (tmp_path / "resolved/dependency/scanner-results.json").is_file()
    assert (tmp_path / "resolved/secret/gitleaks.json").is_file()
    assert (tmp_path / "resolved/codeql/codeql.json").is_file()


def test_newer_mismatched_evidence_fails_closed_without_old_fallback(tmp_path: Path) -> None:
    collected = tmp_path / "collected"
    collected.mkdir()
    _write_lane(collected, lane="dependency", attempt=1)
    _write_lane(collected, lane="dependency", attempt=2, tested_sha="b" * 40)
    _write_lane(collected, lane="secret", attempt=1)
    _write_lane(collected, lane="codeql", attempt=1)

    with pytest.raises(SecurityEvidenceError, match="tested_sha mismatch"):
        resolve_security_evidence(
            collected_root=collected,
            run_id=RUN_ID,
            tested_sha=SHA,
            output_root=tmp_path / "resolved",
        )


def test_newer_failed_evidence_fails_closed(tmp_path: Path) -> None:
    collected = tmp_path / "collected"
    collected.mkdir()
    _write_lane(collected, lane="dependency", attempt=1)
    _write_lane(collected, lane="secret", attempt=1)
    _write_lane(collected, lane="codeql", attempt=1)
    _write_lane(collected, lane="codeql", attempt=3, passed=False)

    with pytest.raises(SecurityEvidenceError, match="not passing evidence"):
        resolve_security_evidence(
            collected_root=collected,
            run_id=RUN_ID,
            tested_sha=SHA,
            output_root=tmp_path / "resolved",
        )


def test_missing_lane_fails_closed(tmp_path: Path) -> None:
    collected = tmp_path / "collected"
    collected.mkdir()
    _write_lane(collected, lane="dependency", attempt=1)
    _write_lane(collected, lane="secret", attempt=1)

    with pytest.raises(SecurityEvidenceError, match="lane=codeql"):
        resolve_security_evidence(
            collected_root=collected,
            run_id=RUN_ID,
            tested_sha=SHA,
            output_root=tmp_path / "resolved",
        )


def test_other_run_ids_are_not_reused(tmp_path: Path) -> None:
    collected = tmp_path / "collected"
    collected.mkdir()
    other = collected / "cml-security-lane-dependency-999999-7"
    other.mkdir()
    (other / "scanner-results.json").write_text(
        json.dumps(
            {
                "schema_version": "cml-security-scan-results-v1",
                "tested_sha": SHA,
                "passed": True,
            }
        ),
        encoding="utf-8",
    )
    _write_lane(collected, lane="secret", attempt=1)
    _write_lane(collected, lane="codeql", attempt=1)

    with pytest.raises(SecurityEvidenceError, match="lane=dependency"):
        resolve_security_evidence(
            collected_root=collected,
            run_id=RUN_ID,
            tested_sha=SHA,
            output_root=tmp_path / "resolved",
        )
