"""Structural input must not be mistaken for valid causal evidence."""

from dataclasses import replace
from itertools import permutations
import subprocess
import sys

import pytest

from cml.audit import AuditConfig, AuditEngine, CustomRule
from cml.chain import find_root, reconstruct_chain
from cml.ctag import CLASS
from cml.record import Actor, CausalRecord, records_to_index


def _record(record_id, parent=None, *, permitted_by="root_event:request", action="exec"):
    return CausalRecord(
        id=record_id, timestamp=1, actor=Actor(pid=1, uid=1),
        action=action, object="/demo", permitted_by=permitted_by,
        parent_cause=parent,
    )


def _approval_engine():
    return AuditEngine(AuditConfig(custom_rules=[CustomRule(
        id="APPROVAL", description="Send must descend from recorded approval",
        trigger_class=CLASS.NET_OUT,
        require_ancestor_permitted_by_prefix="approval:",
        code="DEMO-MISSING-APPROVAL",
    )]))


@pytest.mark.parametrize("order", list(permutations(range(3))))
def test_duplicate_approval_ids_rejected_in_every_order(order):
    records = [
        _record("approval", permitted_by="root_event:request"),
        _record("approval", permitted_by="approval:reviewed"),
        _record("send", "approval", action="send", permitted_by="network:send"),
    ]
    records = [records[i] for i in order]
    for operation in (records_to_index, _approval_engine().run):
        with pytest.raises(ValueError, match="Duplicate record id.*approval"):
            operation(records)


def test_identical_duplicate_is_not_silently_deduplicated():
    record = _record("same")
    with pytest.raises(ValueError, match="Duplicate record id.*same"):
        AuditEngine().run([record, replace(record)])


@pytest.mark.parametrize("size", [1, 2, 3, 300])
@pytest.mark.parametrize("r1_enabled", [True, False])
def test_cycles_fail_even_beyond_walk_limit_or_with_r1_disabled(size, r1_enabled):
    records = [_record(str(i), str((i + 1) % size)) for i in range(size)]
    result = AuditEngine(AuditConfig(rules_enabled={"R1": r1_enabled})).run(records)
    assert not result.passed()
    cycle_findings = [f for f in result.findings if f.code == "CML-AUDIT-R1-CYCLE"]
    assert {f.record_id for f in cycle_findings} == {r.id for r in records}
    assert all(f.severity == "FAIL" for f in cycle_findings)
    assert result.ok == 0


def test_cycle_reached_through_tail_and_disconnected_cycle_are_found_once():
    records = [
        _record("tail", "a"), _record("a", "b"), _record("b", "a"),
        _record("root"), _record("child", "root"), _record("self", "self"),
    ]
    for ordered in (records, list(reversed(records))):
        result = AuditEngine().run(ordered)
        cycles = [f.record_id for f in result.findings if f.code == "CML-AUDIT-R1-CYCLE"]
        assert sorted(cycles) == ["a", "b", "self"]
        assert not result.passed()


@pytest.mark.parametrize("size", [1, 2, 3, 300])
def test_cycle_cannot_be_reported_as_a_root(size):
    records = [_record(str(i), str((i + 1) % size)) for i in range(size)]
    index = records_to_index(records)
    assert find_root("0", index) is None
    # Diagnostic partial walks remain available for backward compatibility.
    assert 0 < len(reconstruct_chain("0", index)) <= 256


def test_missing_parent_is_not_a_root():
    orphan = _record("orphan", "absent")
    assert find_root("orphan", records_to_index([orphan])) is None


def test_depth_limit_is_not_a_root():
    records = [_record(str(i), str(i - 1) if i else None) for i in range(257)]
    index = records_to_index(records)
    assert find_root("256", index) is None
    assert find_root("255", index).id == "0"
    assert find_root("absent", index) is None
    assert AuditEngine().run(records).passed()


def test_valid_branching_and_unique_approval_controls():
    root = _record("root")
    approval = _record("approval", "root", permitted_by="approval:reviewed")
    send = _record("send", "approval", action="send", permitted_by="network:send")
    sibling = _record("sibling", "root")
    assert _approval_engine().run([send, sibling, approval, root]).passed()
    denied = replace(approval, permitted_by="request:unreviewed")
    result = _approval_engine().run([root, denied, send])
    assert not result.passed()
    assert [f.code for f in result.findings] == ["DEMO-MISSING-APPROVAL"]
    assert AuditEngine().run([]).passed()


def test_cli_audit_duplicate_input_has_clean_error(tmp_path):
    record = _record("duplicate")
    path = tmp_path / "duplicate.jsonl"
    path.write_text(record.to_jsonl() + "\n" + record.to_jsonl() + "\n")
    completed = subprocess.run(
        [sys.executable, "-m", "cli.main", "audit", str(path), "--format", "json"],
        capture_output=True, text=True,
    )
    assert completed.returncode == 1
    assert "Duplicate record id" in completed.stderr
    assert "Traceback" not in completed.stderr
    assert '"passed": true' not in completed.stdout


@pytest.mark.parametrize("format_", ["json", "markdown", "text"])
def test_api_audit_rejects_duplicates_in_every_format(format_, monkeypatch):
    from fastapi.testclient import TestClient
    from api import server

    monkeypatch.setattr(server.limiter, "enabled", False)
    record = _record("duplicate")
    response = TestClient(server.app).post("/audit", json={
        "log": record.to_jsonl() + "\n" + record.to_jsonl(), "format": format_,
    })
    assert response.status_code == 422
    assert "Duplicate record id" in response.json()["detail"]


def test_api_audit_reports_cycle_failure(monkeypatch):
    from fastapi.testclient import TestClient
    from api import server

    monkeypatch.setattr(server.limiter, "enabled", False)
    records = [_record("a", "b"), _record("b", "a")]
    response = TestClient(server.app).post("/audit", json={
        "log": "\n".join(r.to_jsonl() for r in records),
    })
    assert response.status_code == 200
    result = response.json()
    assert not result["summary"]["passed"]
    assert {f["code"] for f in result["findings"]} == {"CML-AUDIT-R1-CYCLE"}


def test_cli_adapter_reports_cycle_failure():
    from cli.audit import audit

    result = audit([_record("a", "b").to_dict(), _record("b", "a").to_dict()])
    assert not result["summary"]["passed"]
    assert {f["code"] for f in result["findings"]} == {"CML-AUDIT-R1-CYCLE"}


def test_customer_demo_exposes_approval_evidence_failures():
    from examples.structural_audit_demo import run_demo

    outcomes = run_demo()
    assert {name: result["status"] for name, result in outcomes.items()} == {
        "valid_approval_lineage": "PASS",
        "approval_bypassed": "FAIL",
        "duplicate_approval_identity": "INVALID_INPUT",
        "circular_approval_lineage": "FAIL",
    }
    assert outcomes["approval_bypassed"]["findings"] == ["DEMO-EXPORT-MISSING-APPROVAL"]
    assert set(outcomes["circular_approval_lineage"]["findings"]) == {"CML-AUDIT-R1-CYCLE"}
