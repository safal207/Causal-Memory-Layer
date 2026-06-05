import json
from pathlib import Path

from cml import AuditConfig, AuditEngine
from cml.experimental.cause_band import evaluate_fixture
from cml.record import Actor, CausalRecord
from scripts.run_experimental_cause_band_eval import extract_fixture_payload


FIXTURE_DIR = Path("benchmarks/experimental")
FIXTURE_PATH = FIXTURE_DIR / "07_range_drift_intent.json"
AGENT_EXAMPLE_PATH = Path("examples/agent_intent_drift_trace.json")


def _load_fixture(name: str):
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


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
    assert result["trajectory_direction"] == "degrading"
    assert result["recovered_to_safe"] is False
    assert result["oscillating"] is False
    assert result["duration_threshold"] == 3
    assert result["max_consecutive_outside_safe"] == 3
    assert result["predicted_codes"] == [
        "CML-AUDIT-RANGE-CRITICAL_EXIT",
        "CML-AUDIT-RANGE-DRIFT",
        "CML-AUDIT-RANGE-PERSISTENT_DEVIATION",
    ]
    assert result["matches_expected_future"] is True


def test_experimental_cause_band_eval_detects_recovery_fixture_shape():
    result = evaluate_fixture(_load_fixture("08_range_recovery_intent.json"))

    assert result["case_id"] == "range-recovery-intent-experimental"
    assert result["bands"] == [
        "safe_range",
        "warning_range",
        "danger_range",
        "safe_range",
    ]
    assert result["trajectory_direction"] == "recovering"
    assert result["recovered_to_safe"] is True
    assert result["oscillating"] is False
    assert result["max_consecutive_outside_safe"] == 2
    assert result["predicted_codes"] == ["CML-AUDIT-RANGE-DRIFT"]
    assert result["matches_expected_future"] is True


def test_experimental_cause_band_eval_detects_oscillation_fixture_shape():
    result = evaluate_fixture(_load_fixture("09_range_oscillation_intent.json"))

    assert result["case_id"] == "range-oscillation-intent-experimental"
    assert result["bands"] == [
        "safe_range",
        "warning_range",
        "safe_range",
        "warning_range",
        "danger_range",
    ]
    assert result["trajectory_direction"] == "oscillating"
    assert result["recovered_to_safe"] is True
    assert result["oscillating"] is True
    assert result["max_consecutive_outside_safe"] == 2
    assert result["predicted_codes"] == ["CML-AUDIT-RANGE-DRIFT"]
    assert result["matches_expected_future"] is True


def test_experimental_cause_band_eval_detects_persistent_without_critical_fixture_shape():
    result = evaluate_fixture(_load_fixture("10_range_persistent_without_critical.json"))

    assert result["case_id"] == "range-persistent-without-critical-experimental"
    assert result["bands"] == [
        "safe_range",
        "warning_range",
        "warning_range",
        "danger_range",
    ]
    assert result["trajectory_direction"] == "degrading"
    assert result["recovered_to_safe"] is False
    assert result["oscillating"] is False
    assert result["max_consecutive_outside_safe"] == 3
    assert result["predicted_codes"] == [
        "CML-AUDIT-RANGE-DRIFT",
        "CML-AUDIT-RANGE-PERSISTENT_DEVIATION",
    ]
    assert result["matches_expected_future"] is True


def test_experimental_cause_band_sidecar_adapter_preserves_top_level_fixture():
    raw = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    assert extract_fixture_payload(raw) is raw


def test_experimental_cause_band_sidecar_adapter_evaluates_agent_example():
    raw = json.loads(AGENT_EXAMPLE_PATH.read_text(encoding="utf-8"))

    result = evaluate_fixture(extract_fixture_payload(raw))

    assert result["case_id"] == "agent-intent-drift-sidecar-experimental"
    assert result["bands"] == [
        "safe_range",
        "safe_range",
        "warning_range",
        "danger_range",
        "critical_range",
    ]
    assert result["trajectory_direction"] == "degrading"
    assert result["recovered_to_safe"] is False
    assert result["oscillating"] is False
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
