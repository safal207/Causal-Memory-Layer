"""Pin the quiet-scope cell: an AVAILABLE witness that saw zero reads.

`check_admissibility_preconditions` guards the observation-channel rule with

    if witness.reads_count > 0 and ledger_observations == 0:

so a live witness reporting `reads_count == 0` takes the else branch and returns a full pass. That is
a defensible answer -- for agent memory the modal window really is idle, and making it non-applicable
would fail a genuinely quiet scope closed -- but no test asserts it in either direction.

MEASURED at db6ca00a53f9b04d7c84a5d072fcc16fa3cebf57: flipping the guard to `>= 0` leaves all 67
tests across the seven witness/coverage files passing, so the cell is unexercised whichever way it is
decided.

These two tests change no behaviour. They record the current answer so that a future change to it is
a deliberate edit rather than a silent one, and they fail under exactly that mutation.
"""
from cml.admissibility_preconditions import check_admissibility_preconditions
from cml.external_read_witness import ExternalReadWitness


def _witness(*, reads_count: int, scope_id: str = "scope-a", available: bool = True):
    return ExternalReadWitness(
        source_id="test-witness",
        scope_id=scope_id,
        reads_count=reads_count,
        available=available,
    )


def test_a_live_witness_that_saw_no_reads_is_a_full_pass():
    """The quiet scope. This is the cell the guard's `> 0` decides, and it is the one that would
    flip if the guard became `>= 0`."""
    result = check_admissibility_preconditions(
        witness=_witness(reads_count=0),
        ledger_scope_id="scope-a",
        ledger_observations=0,
    )

    assert result.applicable is True
    assert result.holds is True
    assert result.allows_applicability is True
    assert result.reasons == ()


def test_a_live_witness_that_saw_reads_against_a_silent_ledger_still_fails():
    """The control. If this stopped failing, the test above would be pinning a guard that no longer
    guards anything, and would pass for the wrong reason."""
    result = check_admissibility_preconditions(
        witness=_witness(reads_count=1),
        ledger_scope_id="scope-a",
        ledger_observations=0,
    )

    assert result.applicable is True
    assert result.holds is False
    assert "observation_channel_missing" in result.reasons
