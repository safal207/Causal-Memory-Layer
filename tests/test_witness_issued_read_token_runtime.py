from cml.integrations.witness_issued_read_token_runtime import (
    FAIL,
    PASS,
    evaluate_witness_issued_read_token_runtime_proof,
    kernel_object_id,
)
from cml.record import Action, Actor, CausalRecord

SCOPE = "runtime-proof"
READ_ID = "witness-read:0123456789abcdef0123456789abcdef"
DEVICE = 8 << 20 | 1
INODE = 4242
OBJECT_ID = kernel_object_id(DEVICE, INODE)


def _record(*, read_id: str = READ_ID, object_id: str = OBJECT_ID, action: str = Action.READ):
    return CausalRecord.new(
        actor=Actor(pid=123, uid=1000, ppid=1, comm="proof-child"),
        action=action,
        object_={"fd": 3, "object_id": object_id},
        permitted_by=f"witness_token:{read_id}",
        read_id=read_id,
    )


def _bound(*, read_id: str | None = READ_ID, ret: int = 1, resolved: int = 1):
    return {
        "fd": 3,
        "device": DEVICE,
        "inode": INODE,
        "return_value": ret,
        "started_ns": 100,
        "object_resolved": resolved,
        "token_present": 1 if read_id is not None else 0,
        "read_id": read_id,
    }


def _followup(*, read_id: str | None = None, ret: int = 1):
    return {
        "fd": 3,
        "device": DEVICE,
        "inode": INODE,
        "return_value": ret,
        "started_ns": 200,
        "object_resolved": 1,
        "token_present": 1 if read_id is not None else 0,
        "read_id": read_id,
    }


def _evaluate(**overrides):
    args = {
        "scope_id": SCOPE,
        "issued_read_id": READ_ID,
        "bound_event": _bound(),
        "followup_event": _followup(),
        "ledger_record": _record(),
        "token_consumed": True,
    }
    args.update(overrides)
    return evaluate_witness_issued_read_token_runtime_proof(**args)


def test_exact_witness_kernel_ledger_binding_passes():
    result = _evaluate()

    assert result["status"] == PASS
    assert all(result["assertions"].values())
    assert result["identity_coverage"]["holds"] is True
    assert result["object_coverage"]["holds"] is True


def test_witness_cannot_substitute_a_different_token():
    other = "witness-read:ffffffffffffffffffffffffffffffff"
    result = _evaluate(bound_event=_bound(read_id=other))

    assert result["status"] == FAIL
    assert result["assertions"]["witness_token_matches_issued_token"] is False
    assert result["assertions"]["identity_coverage_holds"] is False


def test_ledger_cannot_invent_a_different_token_after_the_read():
    other = "witness-read:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    result = _evaluate(ledger_record=_record(read_id=other))

    assert result["status"] == FAIL
    assert result["assertions"]["ledger_token_matches_issued_token"] is False
    assert "missing_read_observation" in result["reasons"]


def test_token_must_be_consumed_at_the_use_boundary():
    result = _evaluate(token_consumed=False)

    assert result["status"] == FAIL
    assert result["assertions"]["token_consumed_at_use_boundary"] is False


def test_followup_read_proves_one_shot_token_is_not_reused():
    result = _evaluate(followup_event=_followup(read_id=READ_ID))

    assert result["status"] == FAIL
    assert result["assertions"]["followup_did_not_reuse_token"] is False


def test_object_identity_mismatch_fails_even_when_read_id_matches():
    result = _evaluate(ledger_record=_record(object_id=kernel_object_id(DEVICE, INODE + 1)))

    assert result["status"] == FAIL
    assert result["assertions"]["identity_coverage_holds"] is True
    assert result["assertions"]["object_coverage_holds"] is False
    assert "object_identity_mismatch" in result["reasons"]


def test_failed_boundary_read_cannot_produce_runtime_pass():
    result = _evaluate(bound_event=_bound(ret=-5))

    assert result["status"] == FAIL
    assert result["assertions"]["bound_read_completed_successfully"] is False


def test_non_read_ledger_record_cannot_satisfy_the_contract():
    result = _evaluate(ledger_record=_record(action=Action.OPEN))

    assert result["status"] == FAIL
    assert result["assertions"]["ledger_record_is_read"] is False
    assert result["assertions"]["identity_coverage_holds"] is False
