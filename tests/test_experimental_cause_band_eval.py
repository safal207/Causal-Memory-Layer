import json
from pathlib import Path

from cml.experimental.cause_band import evaluate_fixture


FIXTURE_PATH = Path("benchmarks/experimental/07_range_drift_intent.json")


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
