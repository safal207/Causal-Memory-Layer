import json
from pathlib import Path

from cml import AuditConfig, AuditEngine
from cml.experimental.cause_band import evaluate_fixture
from cml.record import Actor, CausalRecord


FIXTURE_PATH = Path("benchmarks/experimental/07_range_drift_intent.json")


def _valid_records():
    return [
        CausalRecord(
            id="a",
            timestamp=1_000_000_000,
            actor=Actor(pid=100, uid=1000),
            action="exec",
            object="/bin/app",
            permitted_by="root_event:init",
            parent_cause=None,
        ),
        CausalRecord(
            id="b",
            timestamp=1_000_000_001,
            actor=Actor(pid=100, uid=1000),
            action="open",
            object="/tmp/readme.txt",
            permitted_by="fs:read",
            parent_cause="a",
        ),
    ]


def test_experimental_cause_band_eval_matches_future_fixture_expectations():
    raw = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    result = evaluate_fixture(raw)

    assert result["case_id"] == "range-drift-intent-experimental"
    assert result["bands"] == [
        "safe_range",
        "warning_range",
        "danger_range",
        "critical_range",
    ]
    assert result["duration_threshold"] == 3
    assert result["max_consecutive_outside_safe"] == 3
    assert result["predicted_codes"] == [
        "CML-AUDIT-RANGE-CRITICAL_EXIT",
        "CML-AUDIT-RANGE-DRIFT",
        "CML-AUDIT-RANGE-PERSISTENT_DEVIATION",
    ]
    assert result["matches_expected_future"] is True


def test_audit_engine_default_does_not_emit_experimental_cause_band_findings():
    result = AuditEngine().run(_valid_records())

    assert result.passed()
    assert [finding.code for finding in result.findings] == []


def test_audit_engine_emits_experimental_cause_band_findings_only_when_enabled():
    config = AuditConfig(
        enable_experimental_cause_band=True,
        experimental_cause_band_fixture=str(FIXTURE_PATH),
    )

    result = AuditEngine(config).run(_valid_records())

    assert not result.passed()
    assert [finding.code for finding in result.findings] == [
        "CML-AUDIT-RANGE-CRITICAL_EXIT",
        "CML-AUDIT-RANGE-DRIFT",
        "CML-AUDIT-RANGE-PERSISTENT_DEVIATION",
    ]
    assert all(finding.severity == "FAIL" for finding in result.findings)


def test_audit_config_parses_experimental_cause_band_yaml():
    config = AuditConfig.from_yaml_string(
        """
        experimental:
          enable_cause_band: true
          cause_band_fixture: benchmarks/experimental/07_range_drift_intent.json
        """
    )

    assert config.enable_experimental_cause_band is True
    assert config.experimental_cause_band_fixture == str(FIXTURE_PATH)
