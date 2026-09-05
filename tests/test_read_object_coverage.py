import pytest

from cml.external_read_object_witness import (
    ExternalReadObjectBinding,
    ExternalReadObjectWitness,
)
from cml.read_object_coverage import check_causal_record_read_object_coverage
from cml.record import Action, Actor, CausalRecord


def _record(
    read_id: str,
    object_id: str | None,
    *,
    action: str = Action.READ,
    fd: int = 3,
    path: str = "/tmp/data",
) -> CausalRecord:
    obj = {"fd": fd, "path": path}
    if object_id is not None:
        obj["object_id"] = object_id
    return CausalRecord(
        id=f"record-{read_id}-{action}",
        timestamp=1,
        actor=Actor(pid=10, uid=1000),
        action=action,
        object=obj,
        permitted_by="parent_process_context",
        read_id=read_id,
    )


def _witness(*pairs: tuple[str, str], scope_id: str = "session-1"):
    return ExternalReadObjectWitness(
        source_id="vcml-linux-ebpf:sys_exit_read",
        scope_id=scope_id,
        completed_bindings=tuple(
            ExternalReadObjectBinding(read_id=read_id, object_id=object_id)
            for read_id, object_id in pairs
        ),
    )


def test_exact_read_object_binding_passes():
    result = check_causal_record_read_object_coverage(
        witness=_witness(("read-a", "linux-inode:8:101")),
        ledger_scope_id="session-1",
        records=[_record("read-a", "linux-inode:8:101")],
    )

    assert result.applicable is True
    assert result.holds is True
    assert result.allows_applicability is True
    assert result.reasons == ()


def test_same_read_id_with_different_kernel_object_fails():
    result = check_causal_record_read_object_coverage(
        witness=_witness(("read-a", "linux-inode:8:202")),
        ledger_scope_id="session-1",
        records=[_record("read-a", "linux-inode:8:101")],
    )

    assert result.holds is False
    assert result.reasons == ("object_identity_mismatch",)
    assert result.mismatches[0].read_id == "read-a"
    assert result.mismatches[0].expected_object_id == "linux-inode:8:202"
    assert result.mismatches[0].observed_object_id == "linux-inode:8:101"


def test_same_path_cannot_hide_rebound_object():
    result = check_causal_record_read_object_coverage(
        witness=_witness(("read-a", "linux-inode:8:202")),
        ledger_scope_id="session-1",
        records=[
            _record(
                "read-a",
                "linux-inode:8:101",
                path="/tmp/same-name",
            )
        ],
    )

    assert result.holds is False
    assert "object_identity_mismatch" in result.reasons


def test_fd_reuse_is_safe_when_each_read_has_its_own_object_binding():
    result = check_causal_record_read_object_coverage(
        witness=_witness(
            ("read-a", "linux-inode:8:101"),
            ("read-b", "linux-inode:8:202"),
        ),
        ledger_scope_id="session-1",
        records=[
            _record("read-a", "linux-inode:8:101", fd=3),
            _record("read-b", "linux-inode:8:202", fd=3),
        ],
    )

    assert result.holds is True


def test_read_without_object_binding_is_not_exactly_covered():
    result = check_causal_record_read_object_coverage(
        witness=_witness(("read-a", "linux-inode:8:101")),
        ledger_scope_id="session-1",
        records=[_record("read-a", None)],
    )

    assert result.holds is False
    assert result.unbound_read_ids == ("read-a",)
    assert result.reasons == ("missing_object_binding",)


def test_missing_read_entry_is_reported_separately():
    result = check_causal_record_read_object_coverage(
        witness=_witness(("read-a", "linux-inode:8:101")),
        ledger_scope_id="session-1",
        records=[],
    )

    assert result.holds is False
    assert result.missing_read_ids == ("read-a",)
    assert result.reasons == ("missing_read_observation",)


def test_read_exit_cannot_self_prove_object_coverage():
    result = check_causal_record_read_object_coverage(
        witness=_witness(("read-a", "linux-inode:8:101")),
        ledger_scope_id="session-1",
        records=[
            _record(
                "read-a",
                "linux-inode:8:101",
                action="read_exit",
            )
        ],
    )

    assert result.holds is False
    assert result.missing_read_ids == ("read-a",)


def test_foreign_scope_object_witness_cannot_cover_current_ledger():
    result = check_causal_record_read_object_coverage(
        witness=_witness(
            ("read-a", "linux-inode:8:101"),
            scope_id="old-session",
        ),
        ledger_scope_id="current-session",
        records=[_record("read-a", "linux-inode:8:101")],
    )

    assert result.holds is False
    assert result.reasons == ("witness_scope_mismatch",)


def test_unavailable_object_witness_never_passes():
    witness = ExternalReadObjectWitness(
        source_id="kernel",
        scope_id="session-1",
        completed_bindings=(),
        available=False,
    )

    result = check_causal_record_read_object_coverage(
        witness=witness,
        ledger_scope_id="session-1",
        records=[],
    )

    assert result.applicable is False
    assert result.holds is False
    assert result.reasons == ("external_object_witness_unavailable",)


def test_duplicate_persisted_read_id_fails_closed():
    with pytest.raises(ValueError, match="duplicate persisted read_id"):
        check_causal_record_read_object_coverage(
            witness=_witness(("read-a", "linux-inode:8:101")),
            ledger_scope_id="session-1",
            records=[
                _record("read-a", "linux-inode:8:101"),
                _record("read-a", "linux-inode:8:101"),
            ],
        )
