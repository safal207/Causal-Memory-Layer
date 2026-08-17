import pytest

from cml.external_read_witness import ExternalReadIdentityWitness
from cml.read_observation_coverage import (
    check_causal_record_read_observation_coverage,
    check_read_observation_coverage,
    ledger_read_ids_from_causal_records,
)
from cml.record import Action, Actor, CausalRecord


def _witness(*ids: str, scope_id: str = "session-1", available: bool = True):
    return ExternalReadIdentityWitness(
        source_id="vcml-linux-ebpf:sys_exit_read",
        scope_id=scope_id,
        completed_read_ids=tuple(ids) if available else (),
        available=available,
    )


def _record(*, action: str, read_id: str | None) -> CausalRecord:
    return CausalRecord(
        id=f"record-{action}-{read_id or 'legacy'}",
        timestamp=1,
        actor=Actor(pid=1, uid=1),
        action=action,
        object={"fd": 3},
        permitted_by="test",
        read_id=read_id,
    )


def test_exact_read_id_coverage_allows_applicability():
    result = check_read_observation_coverage(
        witness=_witness("read-a", "read-b"),
        ledger_scope_id="session-1",
        ledger_observation_read_ids=["read-a", "read-b"],
    )

    assert result.applicable is True
    assert result.holds is True
    assert result.allows_applicability is True
    assert result.missing_read_ids == ()
    assert result.reasons == ()


def test_equal_counts_cannot_hide_duplicate_plus_missing_read():
    result = check_read_observation_coverage(
        witness=_witness("read-a", "read-b"),
        ledger_scope_id="session-1",
        ledger_observation_read_ids=["read-a", "read-a"],
    )

    assert len(result.externally_completed_read_ids) == 2
    assert result.observed_read_ids == ("read-a",)
    assert result.holds is False
    assert result.allows_applicability is False
    assert result.missing_read_ids == ("read-b",)
    assert result.reasons == ("missing_read_observation",)


def test_extra_ledger_observations_do_not_hide_or_break_external_coverage():
    result = check_read_observation_coverage(
        witness=_witness("read-a"),
        ledger_scope_id="session-1",
        ledger_observation_read_ids=["read-a", "ledger-only"],
    )

    assert result.holds is True
    assert result.missing_read_ids == ()


def test_foreign_scope_identity_witness_cannot_cover_current_ledger():
    result = check_read_observation_coverage(
        witness=_witness("read-a", scope_id="old-session"),
        ledger_scope_id="current-session",
        ledger_observation_read_ids=["read-a"],
    )

    assert result.applicable is True
    assert result.holds is False
    assert result.reasons == ("witness_scope_mismatch",)


def test_unavailable_identity_witness_never_passes():
    result = check_read_observation_coverage(
        witness=_witness(available=False),
        ledger_scope_id="session-1",
        ledger_observation_read_ids=[],
    )

    assert result.applicable is False
    assert result.holds is False
    assert result.allows_applicability is False
    assert result.reasons == ("external_identity_witness_unavailable",)


def test_missing_witness_never_passes():
    result = check_read_observation_coverage(
        witness=None,
        ledger_scope_id="session-1",
        ledger_observation_read_ids=[],
    )

    assert result.applicable is False
    assert result.holds is False


def test_no_completed_external_reads_is_vacuously_covered_when_witness_is_available():
    result = check_read_observation_coverage(
        witness=_witness(),
        ledger_scope_id="session-1",
        ledger_observation_read_ids=[],
    )

    assert result.applicable is True
    assert result.holds is True


def test_invalid_ledger_read_id_fails_closed():
    with pytest.raises(ValueError, match="non-empty string"):
        check_read_observation_coverage(
            witness=_witness("read-a"),
            ledger_scope_id="session-1",
            ledger_observation_read_ids=[""],
        )


def test_identity_witness_rejects_duplicate_external_ids():
    with pytest.raises(ValueError, match="duplicate completed read_id"):
        ExternalReadIdentityWitness(
            source_id="kernel",
            scope_id="session-1",
            completed_read_ids=("read-a", "read-a"),
        )


def test_causal_record_extraction_uses_only_read_entries():
    records = [
        _record(action=Action.READ, read_id="read-a"),
        _record(action="read_exit", read_id="read-a"),
        _record(action=Action.READ, read_id=None),
        _record(action=Action.OPEN, read_id="not-a-read"),
    ]

    assert ledger_read_ids_from_causal_records(records) == ("read-a",)


def test_read_exit_witness_cannot_prove_its_own_ledger_coverage():
    result = check_causal_record_read_observation_coverage(
        witness=_witness("read-a"),
        ledger_scope_id="session-1",
        records=[_record(action="read_exit", read_id="read-a")],
    )

    assert result.holds is False
    assert result.missing_read_ids == ("read-a",)
    assert result.reasons == ("missing_read_observation",)


def test_persisted_read_entries_close_exact_coverage_loop():
    result = check_causal_record_read_observation_coverage(
        witness=_witness("read-a", "read-b"),
        ledger_scope_id="session-1",
        records=[
            _record(action=Action.READ, read_id="read-a"),
            _record(action=Action.READ, read_id="read-b"),
        ],
    )

    assert result.holds is True
    assert result.observed_read_ids == ("read-a", "read-b")


def test_causal_record_extraction_rejects_non_records():
    with pytest.raises(TypeError, match="record 1 must be a CausalRecord"):
        ledger_read_ids_from_causal_records([{"read_id": "read-a"}])  # type: ignore[list-item]
