"""Regression tests for the CLI audit implementation (cli/audit.py).

The CLI ships its own simplified audit engine which historically drifted
from the SDK semantics in cml/audit.py. These tests pin down the
contract: R2 and R4 are mutually exclusive, and the CLI engine produces
the same findings as the SDK for a representative set of inputs.
"""
from __future__ import annotations

from cli.audit import audit
from cml.audit import AuditConfig, AuditEngine
from cml.record import CausalRecord, Actor


def _rec(rid, permitted_by, parent_cause=None, action="exec", obj="/x"):
    return {
        "id": rid,
        "timestamp": 1,
        "actor": {"pid": 1, "uid": 0},
        "action": action,
        "object": obj,
        "permitted_by": permitted_by,
        "parent_cause": parent_cause,
    }


def _rules(findings):
    return sorted({f["rule"] for f in findings if f["rule"] != "OK"})


class TestCliR2R4MutualExclusivity:
    def test_arbitrary_permitted_by_triggers_only_r2(self):
        result = audit([_rec("a", "something")])
        assert _rules(result["findings"]) == ["R2"]

    def test_near_miss_root_label_triggers_only_r4(self):
        result = audit([_rec("a", "root_event")])
        assert _rules(result["findings"]) == ["R4"]

    def test_proper_root_event_is_ok(self):
        result = audit([_rec("a", "root_event:boot")])
        assert _rules(result["findings"]) == []

    def test_unobserved_parent_is_ok(self):
        result = audit([_rec("a", "unobserved_parent")])
        assert _rules(result["findings"]) == []

    def test_each_record_emits_one_finding_at_most(self):
        # Pre-fix bug: a single null-parent record produced both R2 and R4.
        for permitted_by in ("something", "root_event", "weird-label"):
            result = audit([_rec("a", permitted_by)])
            non_ok = [f for f in result["findings"] if f["rule"] != "OK"]
            assert len(non_ok) == 1, (
                f"permitted_by={permitted_by!r} produced {len(non_ok)} findings: "
                f"{[f['rule'] for f in non_ok]}"
            )


class TestCliSdkParity:
    """The CLI engine and the SDK engine should agree on rule outcomes
    for canonical inputs. Drift between them is itself a bug — this test
    is a tripwire."""

    @staticmethod
    def _sdk_codes(records):
        actor = Actor(pid=1, uid=0)
        sdk_records = [
            CausalRecord(
                id=r["id"],
                timestamp=r["timestamp"],
                actor=actor,
                action=r["action"],
                object=r["object"],
                permitted_by=r["permitted_by"],
                parent_cause=r["parent_cause"],
            )
            for r in records
        ]
        result = AuditEngine(AuditConfig()).run(sdk_records)
        return sorted({f.code.split("-")[2] for f in result.findings})

    @staticmethod
    def _cli_codes(records):
        result = audit(records)
        return sorted({
            f["code"].split("-")[2]
            for f in result["findings"]
            if f["rule"] != "OK"
        })

    def test_arbitrary_label_agreement(self):
        recs = [_rec("a", "something")]
        assert self._cli_codes(recs) == self._sdk_codes(recs) == ["R2"]

    def test_near_miss_root_agreement(self):
        recs = [_rec("a", "root_event")]
        assert self._cli_codes(recs) == self._sdk_codes(recs) == ["R4"]

    def test_proper_root_agreement(self):
        recs = [_rec("a", "root_event:boot")]
        assert self._cli_codes(recs) == self._sdk_codes(recs) == []

    def test_unobserved_parent_agreement(self):
        recs = [_rec("a", "unobserved_parent")]
        assert self._cli_codes(recs) == self._sdk_codes(recs) == []
