from cml.admissibility_preconditions import check_admissibility_preconditions
from cml.external_read_witness import ExternalReadWitness


def _witness(*, reads_count: int, available: bool = True, scope_id: str = "session-1"):
    return ExternalReadWitness(
        source_id="kernel-ebpf",
        scope_id=scope_id,
        reads_count=reads_count,
        available=available,
    )


def test_healthy_witness_allows_applicability():
    result = check_admissibility_preconditions(
        witness=_witness(reads_count=3),
        ledger_scope_id="session-1",
        ledger_observations=3,
        identifier_written="session-1",
        identifier_queried="session-1",
    )

    assert result.applicable is True
    assert result.holds is True
    assert result.allows_applicability is True
    assert result.reasons == ()


def test_dead_collector_from_start_is_detected():
    result = check_admissibility_preconditions(
        witness=_witness(reads_count=1),
        ledger_scope_id="session-1",
        ledger_observations=0,
    )

    assert result.applicable is True
    assert result.holds is False
    assert result.allows_applicability is False
    assert result.reasons == ("observation_channel_missing",)


def test_identifier_mismatch_fails_before_record_applicability():
    result = check_admissibility_preconditions(
        witness=_witness(reads_count=1),
        ledger_scope_id="session-1",
        ledger_observations=1,
        identifier_written="session-1",
        identifier_queried="session-123456",
    )

    assert result.applicable is True
    assert result.holds is False
    assert result.reasons == ("identifier_mismatch",)


def test_unavailable_external_witness_is_not_counted_as_passed():
    result = check_admissibility_preconditions(
        witness=_witness(reads_count=0, available=False),
        ledger_scope_id="session-1",
        ledger_observations=0,
    )

    assert result.applicable is False
    assert result.holds is False
    assert result.allows_applicability is False
    assert result.reasons == ("external_witness_unavailable",)


def test_witness_from_foreign_scope_cannot_cover_current_ledger():
    result = check_admissibility_preconditions(
        witness=_witness(reads_count=2, scope_id="session-old"),
        ledger_scope_id="session-current",
        ledger_observations=2,
    )

    assert result.applicable is True
    assert result.holds is False
    assert result.reasons == ("witness_scope_mismatch",)
