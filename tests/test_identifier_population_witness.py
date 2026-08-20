from __future__ import annotations

import json
from pathlib import Path

import pytest

from cml.integrations.identifier_population_witness import (
    FoldMeasurement,
    HistoricalCollisionRecord,
    HistoricalKeyLedger,
    IdentifierKeyRecord,
    IdentifierPopulationSnapshot,
    issue_identifier_population_witness,
    key_digest,
    validate_identifier_population_witness,
)

FIXTURE = Path(__file__).parent / "fixtures" / "identifier_population_witness_v0.1.json"
MEASURED_AT = "2026-08-20T03:30:00Z"


def _snapshot(payload: dict) -> IdentifierPopulationSnapshot:
    return IdentifierPopulationSnapshot(
        scope=payload["scope"],
        records=tuple(IdentifierKeyRecord(**item) for item in payload["records"]),
        complete=payload.get("complete", True),
    )


def _history(payload: dict | None, snapshot: IdentifierPopulationSnapshot):
    if payload is None:
        return None
    return HistoricalKeyLedger(
        scope=snapshot.scope,
        key_digests=tuple(key_digest(key) for key in payload["keys"]),
        complete=payload["complete"],
    )


def _collisions(payload: list[dict], snapshot: IdentifierPopulationSnapshot):
    records = []
    for item in payload:
        observed = item["observed_population_commitment"]
        if observed == "$INITIAL":
            observed = snapshot.population_commitment
        records.append(
            HistoricalCollisionRecord(
                collision_id=item["collision_id"],
                scope=snapshot.scope,
                fold=item["fold"],
                observed_population_commitment=observed,
            )
        )
    return tuple(records)


def _issue(initial: dict):
    snapshot = _snapshot(initial)
    return issue_identifier_population_witness(
        snapshot,
        [FoldMeasurement(**item) for item in initial["folds"]],
        measured_at=MEASURED_AT,
        identifier_policy_digest=initial["policy_digest"],
        identifier_policy_epoch=initial["policy_epoch"],
        history=_history(initial.get("history"), snapshot),
        historical_collisions=_collisions(
            initial.get("historical_collisions", []), snapshot
        ),
    )


def _run_scenario(scenario: dict):
    witness = _issue(scenario["initial"])
    use = scenario["use"]
    result = validate_identifier_population_witness(
        witness,
        _snapshot(use),
        expected_scope=use["expected_scope"],
        current_policy_digest=use["policy_digest"],
        current_policy_epoch=use["policy_epoch"],
    )
    return witness, result


def test_identifier_population_witness_fixtures() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    contract = payload["benchmark_contract"]
    assert contract["negative_control_required"] is True
    assert len(payload["cases"]) == contract["expected_cases"] == 5
    assert contract["excluded_cases"] == 0

    for case in payload["cases"]:
        _, result = _run_scenario(case)
        expected = case["expected"]
        assert result.measurement_valid_for_use is expected[
            "measurement_valid_for_use"
        ], case["id"]
        assert result.must_recompute is expected["must_recompute"], case["id"]
        assert result.reasons == tuple(expected["reasons"]), case["id"]
        assert result.historical_integrity_available is expected[
            "historical_integrity_available"
        ], case["id"]
        assert result.historical_collision_ids == tuple(
            expected["historical_collision_ids"]
        ), case["id"]
        assert result.at_cliff_edge == tuple(expected["at_cliff_edge"]), case["id"]

        _, control = _run_scenario(case["negative_control"])
        assert control.measurement_valid_for_use is True, case["id"]
        assert control.must_recompute is False, case["id"]
        assert control.reasons == (), case["id"]


def test_population_commitment_distinguishes_same_count_different_keys() -> None:
    left = IdentifierPopulationSnapshot(
        scope="tenant-a",
        records=tuple(IdentifierKeyRecord(key=value) for value in ("a", "b", "c")),
    )
    right = IdentifierPopulationSnapshot(
        scope="tenant-a",
        records=tuple(IdentifierKeyRecord(key=value) for value in ("a", "b", "d")),
    )

    assert left.population_count == right.population_count == 3
    assert left.population_commitment != right.population_commitment


def test_deleted_collision_remains_visible_after_recompute() -> None:
    policy = "policy-v1"
    epoch = "1"
    initial = IdentifierPopulationSnapshot(
        scope="tenant-a",
        records=(
            IdentifierKeyRecord("abc1", policy, epoch),
            IdentifierKeyRecord("abc2", policy, epoch),
        ),
    )
    history = HistoricalKeyLedger(
        scope="tenant-a",
        key_digests=(key_digest("abc1"), key_digest("abc2")),
        complete=True,
    )
    collision = HistoricalCollisionRecord(
        collision_id="collision-abc-prefix-3",
        scope="tenant-a",
        fold="prefix_3",
        observed_population_commitment=initial.population_commitment,
    )
    first = issue_identifier_population_witness(
        initial,
        (FoldMeasurement("prefix_3", "COST_MEASURED", 1, 3, 0, 1),),
        measured_at=MEASURED_AT,
        identifier_policy_digest=policy,
        identifier_policy_epoch=epoch,
        history=history,
        historical_collisions=(collision,),
    )

    after_delete = IdentifierPopulationSnapshot(
        scope="tenant-a",
        records=(IdentifierKeyRecord("abc1", policy, epoch),),
    )
    stale = validate_identifier_population_witness(
        first,
        after_delete,
        expected_scope="tenant-a",
        current_policy_digest=policy,
        current_policy_epoch=epoch,
    )
    assert stale.reasons == ("population_changed",)
    assert stale.historical_collision_ids == ("collision-abc-prefix-3",)

    recomputed = issue_identifier_population_witness(
        after_delete,
        (FoldMeasurement("prefix_3", "ZERO_AT_SCALE", 0, 0, 3, 2),),
        measured_at=MEASURED_AT,
        identifier_policy_digest=policy,
        identifier_policy_epoch=epoch,
        history=history,
        historical_collisions=(collision,),
    )
    current = validate_identifier_population_witness(
        recomputed,
        after_delete,
        expected_scope="tenant-a",
        current_policy_digest=policy,
        current_policy_epoch=epoch,
    )

    assert current.measurement_valid_for_use is True
    assert current.historical_integrity_available is True
    assert current.historical_collision_ids == ("collision-abc-prefix-3",)


def test_incomplete_population_cannot_issue_exact_witness() -> None:
    snapshot = IdentifierPopulationSnapshot(
        scope="tenant-a",
        records=(IdentifierKeyRecord("a", "policy-v1", "1"),),
        complete=False,
    )
    with pytest.raises(ValueError, match="incomplete population snapshot"):
        issue_identifier_population_witness(
            snapshot,
            (),
            measured_at=MEASURED_AT,
            identifier_policy_digest="policy-v1",
            identifier_policy_epoch="1",
        )


def test_unknown_writer_policy_fails_closed_without_erasing_measurement() -> None:
    snapshot = IdentifierPopulationSnapshot(
        scope="tenant-a",
        records=(IdentifierKeyRecord("legacy-key"),),
    )
    witness = issue_identifier_population_witness(
        snapshot,
        (FoldMeasurement("prefix_8", "ZERO_AT_SCALE", 0, 0, 8, 10),),
        measured_at=MEASURED_AT,
        identifier_policy_digest="policy-v2",
        identifier_policy_epoch="2",
    )
    result = validate_identifier_population_witness(
        witness,
        snapshot,
        expected_scope="tenant-a",
        current_policy_digest="policy-v2",
        current_policy_epoch="2",
    )

    assert witness.writer_contract_coverage == 0.0
    assert result.reasons == ("writer_policy_unbound",)
    assert result.measurement_valid_for_use is False


def test_foreign_historical_scope_is_rejected_at_issue_time() -> None:
    snapshot = IdentifierPopulationSnapshot(
        scope="tenant-a",
        records=(IdentifierKeyRecord("a", "policy-v1", "1"),),
    )
    history = HistoricalKeyLedger(
        scope="tenant-b",
        key_digests=(key_digest("a"),),
        complete=True,
    )
    with pytest.raises(ValueError, match="ledger scope must match"):
        issue_identifier_population_witness(
            snapshot,
            (),
            measured_at=MEASURED_AT,
            identifier_policy_digest="policy-v1",
            identifier_policy_epoch="1",
            history=history,
        )
