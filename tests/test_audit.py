"""Tests for the audit engine (R1–R4)"""

import pytest
from cml import load_jsonl, AuditEngine, AuditConfig, Severity
from cml.record import CausalRecord, Actor


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


class TestR1_ReferenceIntegrity:
    def test_missing_parent_is_fail(self):
        records = [
            _rec("a", "exec", "/bin/sh", "root_event:init"),
            _rec("b", "open", "/etc/passwd", "fs:read", parent_cause="NONEXISTENT"),
        ]
        result = AuditEngine().run(records)
        codes = [f.code for f in result.findings]
        assert "CML-AUDIT-R1-MISSING_PARENT" in codes
        fails = [f for f in result.findings if f.severity == Severity.FAIL]
        assert any(f.code == "CML-AUDIT-R1-MISSING_PARENT" for f in fails)

    def test_valid_parent_no_r1(self):
        records = [
            _rec("a", "exec", "/bin/sh", "root_event:init"),
            _rec("b", "open", "/etc/passwd", "fs:read", parent_cause="a"),
        ]
        result = AuditEngine().run(records)
        codes = [f.code for f in result.findings]
        assert "CML-AUDIT-R1-MISSING_PARENT" not in codes


class TestR2_GapMarking:
    def test_gap_not_marked_is_warn(self):
        records = [
            _rec("a", "exec", "/bin/sh", "some_unrelated_thing", parent_cause=None),
        ]
        result = AuditEngine().run(records)
        codes = [f.code for f in result.findings]
        assert "CML-AUDIT-R2-GAP_NOT_MARKED" in codes

    def test_gap_marked_unobserved_no_r2(self):
        records = [
            _rec("a", "exec", "/bin/sh", "unobserved_parent", parent_cause=None),
        ]
        result = AuditEngine().run(records)
        r2 = [f for f in result.findings if f.code == "CML-AUDIT-R2-GAP_NOT_MARKED"]
        assert len(r2) == 0

    def test_root_event_no_r2(self):
        records = [
            _rec("a", "exec", "/sbin/init", "root_event:system_boot", parent_cause=None),
        ]
        result = AuditEngine().run(records)
        r2 = [f for f in result.findings if f.code == "CML-AUDIT-R2-GAP_NOT_MARKED"]
        assert len(r2) == 0


class TestR3_SecretNetChain:
    def test_secret_then_net_no_link_is_fail(self):
        # All three records share pid=100 so R3 sees NET_OUT after a SECRET
        # in the same PID. "c" has parent_cause=None so ancestors("c")={c},
        # which has no intersection with secret_ids={"b"} — R3 fires.
        records = [
            _rec("a", "exec", "/bin/myapp", "root_event:init", pid=100),
            _rec("b", "open", {"path": "/secrets/api.key", "classification": "SECRET"},
                 "fs:read", parent_cause="a", pid=100),
            _rec("c", "connect", {"addr": "1.2.3.4", "port": 443},
                 "unobserved_parent", parent_cause=None, pid=100),  # no link back to b
        ]
        result = AuditEngine().run(records)
        r3 = [f for f in result.findings if f.code == "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN"]
        assert len(r3) == 1
        assert r3[0].severity == Severity.FAIL

    def test_secret_then_net_with_chain_no_r3(self):
        records = [
            _rec("a", "exec", "/bin/myapp", "root_event:init"),
            _rec("b", "open", {"path": "/secrets/api.key", "classification": "SECRET"},
                 "fs:read", parent_cause="a"),
            _rec("c", "connect", {"addr": "1.2.3.4", "port": 443},
                 "net:egress", parent_cause="b"),  # linked to secret
        ]
        result = AuditEngine().run(records)
        r3 = [f for f in result.findings if f.code == "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN"]
        assert len(r3) == 0

    def test_net_without_prior_secret_no_r3(self):
        records = [
            _rec("a", "exec", "/bin/myapp", "root_event:init"),
            _rec("b", "connect", {"addr": "1.2.3.4", "port": 80},
                 "net:egress", parent_cause="a"),
        ]
        result = AuditEngine().run(records)
        r3 = [f for f in result.findings if f.code == "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN"]
        assert len(r3) == 0

    def test_indirect_chain_is_ok(self):
        """Chain: exec → secret_open → secret_read → connect — should pass R3"""
        records = [
            _rec("a", "exec", "/bin/myapp", "root_event:init"),
            _rec("b", "open", {"path": "/secrets/key", "classification": "SECRET"},
                 "fs:read", parent_cause="a"),
            _rec("c", "read", {"path": "/secrets/key", "classification": "SECRET"},
                 "b", parent_cause="b"),
            _rec("d", "connect", {"addr": "5.5.5.5", "port": 443},
                 "net:egress", parent_cause="c"),
        ]
        result = AuditEngine().run(records)
        r3 = [f for f in result.findings if f.code == "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN"]
        assert len(r3) == 0


class TestR4_AmbiguousRoot:
    def test_near_miss_root_label_fires_r4(self):
        # "root_event" (missing colon) looks like a malformed root_event: label.
        records = [
            _rec("a", "exec", "/bin/myapp", "root_event", parent_cause=None),
        ]
        result = AuditEngine().run(records)
        r4 = [f for f in result.findings if f.code == "CML-AUDIT-R4-AMBIGUOUS_ROOT"]
        assert len(r4) == 1
        assert r4[0].severity == Severity.WARN

    def test_near_miss_fires_r4_not_r2(self):
        # Near-miss root labels should trigger R4 only, not R2.
        records = [
            _rec("a", "exec", "/bin/myapp", "root_event", parent_cause=None),
        ]
        result = AuditEngine().run(records)
        codes = [f.code for f in result.findings]
        assert "CML-AUDIT-R4-AMBIGUOUS_ROOT" in codes
        assert "CML-AUDIT-R2-GAP_NOT_MARKED" not in codes

    def test_arbitrary_permitted_by_fires_r2_not_r4(self):
        # Arbitrary permitted_by → R2 (gap not marked), not R4 (no root resemblance).
        records = [
            _rec("a", "exec", "/bin/myapp", "some_context", parent_cause=None),
        ]
        result = AuditEngine().run(records)
        codes = [f.code for f in result.findings]
        assert "CML-AUDIT-R2-GAP_NOT_MARKED" in codes
        assert "CML-AUDIT-R4-AMBIGUOUS_ROOT" not in codes

    def test_unobserved_parent_no_r2_no_r4(self):
        # Correctly labeled gap: neither rule fires.
        records = [
            _rec("a", "exec", "/bin/myapp", "unobserved_parent", parent_cause=None),
        ]
        result = AuditEngine().run(records)
        codes = [f.code for f in result.findings]
        assert "CML-AUDIT-R2-GAP_NOT_MARKED" not in codes
        assert "CML-AUDIT-R4-AMBIGUOUS_ROOT" not in codes

    def test_root_event_prefix_no_r4(self):
        records = [
            _rec("a", "exec", "/sbin/init", "root_event:system_boot"),
        ]
        result = AuditEngine().run(records)
        r4 = [f for f in result.findings if f.code == "CML-AUDIT-R4-AMBIGUOUS_ROOT"]
        assert len(r4) == 0

    def test_custom_prefix_near_miss_fires_r4(self):
        # Custom prefix "init::" — "init:" is a near-miss (missing second colon).
        cfg = AuditConfig(root_event_prefix="init::")
        records = [
            _rec("a", "exec", "/sbin/init", "init:", parent_cause=None),
        ]
        result = AuditEngine(cfg).run(records)
        codes = [f.code for f in result.findings]
        assert "CML-AUDIT-R4-AMBIGUOUS_ROOT" in codes
        assert "CML-AUDIT-R2-GAP_NOT_MARKED" not in codes

    def test_custom_prefix_valid_root_no_r4(self):
        cfg = AuditConfig(root_event_prefix="init::")
        records = [
            _rec("a", "exec", "/sbin/init", "init::boot", parent_cause=None),
        ]
        result = AuditEngine(cfg).run(records)
        r4 = [f for f in result.findings if f.code == "CML-AUDIT-R4-AMBIGUOUS_ROOT"]
        assert len(r4) == 0


class TestFromYamlString:
    def test_empty_yaml_returns_defaults(self):
        cfg = AuditConfig.from_yaml_string("")
        assert cfg.root_event_prefix == "root_event:"

    def test_null_yaml_returns_defaults(self):
        cfg = AuditConfig.from_yaml_string("---")
        assert cfg.root_event_prefix == "root_event:"


class TestExampleLogs:
    def test_exec_log_passes(self):
        records = load_jsonl("examples/exec_causal_log.jsonl")
        result = AuditEngine().run(records)
        fails = [f for f in result.findings if f.severity == Severity.FAIL]
        assert len(fails) == 0

    def test_secret_net_log_has_r3_fail(self):
        records = load_jsonl("examples/secret_to_net_log.jsonl")
        result = AuditEngine().run(records)
        r3 = [f for f in result.findings
              if f.code == "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN"]
        assert len(r3) >= 1
