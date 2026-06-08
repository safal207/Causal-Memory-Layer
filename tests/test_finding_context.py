"""Tests for optional Finding.context support."""

from cml import AuditConfig, AuditEngine, Severity
from cml.record import Actor, CausalRecord


def _rec(id_, action, object_, permitted_by, parent_cause=None, pid=100):
    return CausalRecord(
        id=id_,
        timestamp=1_000_000_000,
        actor=Actor(pid=pid, uid=1000),
        action=action,
        object=object_,
        permitted_by=permitted_by,
        parent_cause=parent_cause,
    )


def test_context_is_omitted_by_default_for_r1():
    records = [
        _rec("a", "exec", "/bin/sh", "root_event:init"),
        _rec("b", "open", "/etc/passwd", "fs:read", parent_cause="missing"),
    ]

    result = AuditEngine().run(records)
    finding = next(f for f in result.findings if f.code == "CML-AUDIT-R1-MISSING_PARENT")

    assert finding.context == {}
    assert "context" not in finding.to_dict()


def test_include_context_adds_r1_context():
    records = [
        _rec("a", "exec", "/bin/sh", "root_event:init"),
        _rec("b", "open", "/etc/passwd", "fs:read", parent_cause="missing"),
    ]

    result = AuditEngine(AuditConfig(include_context=True)).run(records)
    finding = next(f for f in result.findings if f.code == "CML-AUDIT-R1-MISSING_PARENT")

    assert finding.severity == Severity.FAIL
    assert finding.context["missing_parent"] == "missing"
    assert finding.context["record_action"] == "open"
    assert finding.context["record_permitted_by"] == "fs:read"
    assert finding.context["known_record_count"] == 2
    assert finding.to_dict()["context"] == finding.context


def test_include_context_adds_r3_context():
    records = [
        _rec("a", "exec", "/bin/myapp", "root_event:init", pid=100),
        _rec(
            "b",
            "open",
            {"path": "/secrets/api.key", "classification": "SECRET"},
            "fs:read",
            parent_cause="a",
            pid=100,
        ),
        _rec(
            "c",
            "connect",
            {"addr": "1.2.3.4", "port": 443},
            "unobserved_parent",
            parent_cause=None,
            pid=100,
        ),
    ]

    result = AuditEngine(AuditConfig(include_context=True)).run(records)
    finding = next(
        f for f in result.findings
        if f.code == "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN"
    )

    assert finding.severity == Severity.FAIL
    assert finding.chain_ids == ["b"]
    assert finding.context["pid"] == 100
    assert finding.context["net_out_action"] == "connect"
    assert finding.context["preceding_secret_ids"] == ["b"]
    assert finding.context["ancestor_ids"] == []


def test_include_context_can_be_loaded_from_yaml_string():
    cfg = AuditConfig.from_yaml_string("include_context: true")

    assert cfg.include_context is True

    records = [
        _rec("a", "exec", "/bin/sh", "root_event:init"),
        _rec("b", "open", "/etc/passwd", "fs:read", parent_cause="missing"),
    ]

    result = AuditEngine(cfg).run(records)
    finding = next(f for f in result.findings if f.code == "CML-AUDIT-R1-MISSING_PARENT")

    assert finding.context["missing_parent"] == "missing"
