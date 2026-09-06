import copy
import importlib.util
import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = REPO_ROOT / "benchmarks" / "equilibrium" / "run.py"
FIXTURES_PATH = REPO_ROOT / "benchmarks" / "equilibrium" / "v1" / "fixtures.json"


def _load_runner() -> Any:
    spec = importlib.util.spec_from_file_location("cml_equilibrium_benchmark", RUNNER_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = _load_runner()


def _write_contract(path: Path, contract: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(contract, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_runner_reproduces_all_published_fixtures() -> None:
    contract = runner.load_contract(FIXTURES_PATH)
    original = copy.deepcopy(contract)

    report = runner.run_benchmark(
        contract,
        implementation_commit="test-commit",
    )

    assert report["report_schema_version"] == "cml-equilibrium-report-v1"
    assert report["implementation_commit"] == "test-commit"
    assert report["total"] == 10
    assert report["passed"] == 10
    assert report["failed"] == 0
    assert report["state_counts"] == {
        "BALANCED": 2,
        "UNSTABLE": 3,
        "INDETERMINATE": 5,
    }
    assert [item["fixture_id"] for item in report["fixtures"]] == sorted(
        item["fixture_id"] for item in report["fixtures"]
    )
    assert contract == original


def test_report_serialization_is_deterministic() -> None:
    contract = runner.load_contract(FIXTURES_PATH)
    first = runner.run_benchmark(contract, implementation_commit="same-commit")
    second = runner.run_benchmark(contract, implementation_commit="same-commit")

    assert runner.json_report_text(first) == runner.json_report_text(second)
    assert runner.markdown_report_text(first) == runner.markdown_report_text(second)


def test_cli_writes_json_and_markdown_reports(tmp_path: Path, capsys: Any) -> None:
    json_out = tmp_path / "report.json"
    markdown_out = tmp_path / "report.md"

    exit_code = runner.main(
        [
            "--fixtures",
            str(FIXTURES_PATH),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
            "--implementation-commit",
            "cli-test-commit",
        ]
    )

    assert exit_code == 0
    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert report["passed"] == 10
    assert report["failed"] == 0
    assert report["implementation_commit"] == "cli-test-commit"
    markdown = markdown_out.read_text(encoding="utf-8")
    assert "**Result:** `PASS`" in markdown
    assert "eq_v1_010_multiple_findings_canonical_order" in markdown
    assert "JSON SHA-256:" in capsys.readouterr().out


def test_cli_returns_nonzero_and_reports_semantic_mismatch(
    tmp_path: Path,
) -> None:
    contract = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))
    contract["fixtures"][0]["expected_state"] = "UNSTABLE"
    fixtures_path = tmp_path / "mismatch.json"
    _write_contract(fixtures_path, contract)
    json_out = tmp_path / "mismatch-report.json"
    markdown_out = tmp_path / "mismatch-report.md"

    exit_code = runner.main(
        [
            "--fixtures",
            str(fixtures_path),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
            "--implementation-commit",
            "mismatch-commit",
        ]
    )

    assert exit_code == 1
    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert report["passed"] == 9
    assert report["failed"] == 1
    failed = [item for item in report["fixtures"] if not item["passed"]]
    assert [item["fixture_id"] for item in failed] == [
        "eq_v1_001_balanced_full_context"
    ]
    assert "## Mismatches" in markdown_out.read_text(encoding="utf-8")


def test_cli_rejects_malformed_fixture_input(
    tmp_path: Path,
    capsys: Any,
) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"fixtures": [', encoding="utf-8")
    json_out = tmp_path / "should-not-exist.json"
    markdown_out = tmp_path / "should-not-exist.md"

    exit_code = runner.main(
        [
            "--fixtures",
            str(malformed),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
            "--implementation-commit",
            "bad-input-commit",
        ]
    )

    assert exit_code == 2
    assert not json_out.exists()
    assert not markdown_out.exists()
    assert "benchmark input error" in capsys.readouterr().err


def test_contract_rejects_noncanonical_expected_finding_order(
    tmp_path: Path,
) -> None:
    contract = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))
    findings = contract["fixtures"][-1]["expected_findings"]
    findings[2], findings[3] = findings[3], findings[2]
    fixtures_path = tmp_path / "wrong-order.json"
    _write_contract(fixtures_path, contract)

    try:
        runner.load_contract(fixtures_path)
    except runner.BenchmarkInputError as exc:
        assert "canonical order" in str(exc)
    else:
        raise AssertionError("noncanonical findings order was accepted")
