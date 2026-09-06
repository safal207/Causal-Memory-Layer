from __future__ import annotations

import json
from pathlib import Path

import pytest

from cml.integrations.identifier_population_witness import (
    IDENTIFIER_MEASUREMENT_PREDICATE,
    POPULATION_COMMITMENT_FIELDS,
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
        population_basis=payload.get("population_basis", "lookup_keyspace"),
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
        expected_population_basis=use.get(
            "expected_population_basis", "lookup_keyspace"
        ),
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


def test_population_basis_is_bound_and_declares_commitment_scope() -> None:
    policy = "policy-v1"
    epoch = "1"
    records = (IdentifierKeyRecord("scratchpad/httpfail.mjs", policy, epoch),)
    surviving_sources = IdentifierPopulationSnapshot(
        scope="tenant-a",
        records=records,
        population_basis="surviving_sources",
    )
    lookup_keyspace = IdentifierPopulationSnapshot(
        scope="tenant-a",
        records=records,
        population_basis="lookup_keyspace",
    )

    assert surviving_sources.population_commitment != lookup_keyspace.population_commitment

    witness = issue_identifier_population_witness(
        surviving_sources,
        (FoldMeasurement("prefix_122", "ZERO_AT_SCALE", 0, 149, 27, 634),),
        measured_at=MEASURED_AT,
        identifier_policy_digest=policy,
        identifier_policy_epoch=epoch,
    )

    assert witness.population_commitment_fields == POPULATION_COMMITMENT_FIELDS
    assert witness.measurement_predicate == IDENTIFIER_MEASUREMENT_PREDICATE

    stale_by_basis = validate_identifier_population_witness(
        witness,
        surviving_sources,
        expected_scope="tenant-a",
        current_policy_digest=policy,
        current_policy_epoch=epoch,
        expected_population_basis="lookup_keyspace",
    )
    assert stale_by_basis.measurement_valid_for_use is False
    assert stale_by_basis.reasons == ("population_basis_mismatch",)

    control = validate_identifier_population_witness(
        witness,
        surviving_sources,
        expected_scope="tenant-a",
        current_policy_digest=policy,
        current_policy_epoch=epoch,
        expected_population_basis="surviving_sources",
    )
    assert control.measurement_valid_for_use is True
    assert control.reasons == ()


def test_complete_empty_population_has_vacuous_full_coverage() -> None:
    policy = "policy-v1"
    epoch = "1"
    snapshot = IdentifierPopulationSnapshot(scope="tenant-a", records=())
    history = HistoricalKeyLedger(scope="tenant-a", key_digests=(), complete=True)

    witness = issue_identifier_population_witness(
        snapshot,
        (),
        measured_at=MEASURED_AT,
        identifier_policy_digest=policy,
        identifier_policy_epoch=epoch,
        history=history,
    )
    result = validate_identifier_population_witness(
        witness,
        snapshot,
        expected_scope="tenant-a",
        current_policy_digest=policy,
        current_policy_epoch=epoch,
    )

    assert witness.writer_contract_coverage == 1.0
    assert witness.historical_key_coverage == 1.0
    assert result.historical_integrity_available is True
    assert result.measurement_valid_for_use is True
    assert result.reasons == ()


def test_historical_collision_retains_full_binding_evidence() -> None:
    policy = "policy-v1"
    epoch = "1"
    snapshot = IdentifierPopulationSnapshot(
        scope="tenant-a",
        records=(IdentifierKeyRecord("abc1", policy, epoch),),
    )
    first_collision = HistoricalCollisionRecord(
        collision_id="collision-1",
        scope="tenant-a",
        fold="prefix_3",
        observed_population_commitment=snapshot.population_commitment,
    )
    rebound_collision = HistoricalCollisionRecord(
        collision_id="collision-1",
        scope="tenant-a",
        fold="prefix_4",
        observed_population_commitment="other-population-commitment",
    )

    first = issue_identifier_population_witness(
        snapshot,
        (),
        measured_at=MEASURED_AT,
        identifier_policy_digest=policy,
        identifier_policy_epoch=epoch,
        historical_collisions=(first_collision,),
    )
    rebound = issue_identifier_population_witness(
        snapshot,
        (),
        measured_at=MEASURED_AT,
        identifier_policy_digest=policy,
        identifier_policy_epoch=epoch,
        historical_collisions=(rebound_collision,),
    )

    assert first.historical_collision_ids == rebound.historical_collision_ids == (
        "collision-1",
    )
    assert first.historical_collision_records == (first_collision,)
    assert rebound.historical_collision_records == (rebound_collision,)
    assert first.historical_collision_records != rebound.historical_collision_records

    validated = validate_identifier_population_witness(
        first,
        snapshot,
        expected_scope="tenant-a",
        current_policy_digest=policy,
        current_policy_epoch=epoch,
    )
    assert validated.historical_collision_records == (first_collision,)
    assert validated.historical_collision_ids == ("collision-1",)


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
    assert stale.historical_collision_records == (collision,)

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
    assert current.historical_collision_records == (collision,)


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
