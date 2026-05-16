"""Tests for CausalRecord.from_dict input validation."""
from __future__ import annotations

import pytest

from cml.record import CausalRecord


VALID = {
    "id": "x",
    "timestamp": 1,
    "actor": {"pid": 1, "uid": 0},
    "action": "exec",
    "object": "/bin/sh",
    "permitted_by": "root_event:init",
}


def test_from_dict_round_trips_valid_payload():
    rec = CausalRecord.from_dict(VALID)
    assert rec.id == "x"
    assert rec.actor.pid == 1


@pytest.mark.parametrize(
    "missing",
    ["id", "timestamp", "actor", "action", "object", "permitted_by"],
)
def test_from_dict_reports_each_missing_field(missing):
    payload = {k: v for k, v in VALID.items() if k != missing}
    with pytest.raises(ValueError) as exc:
        CausalRecord.from_dict(payload)
    assert missing in str(exc.value)


def test_from_dict_reports_all_missing_fields_at_once():
    payload = {"id": "x", "timestamp": 1}
    with pytest.raises(ValueError) as exc:
        CausalRecord.from_dict(payload)
    msg = str(exc.value)
    for field in ("actor", "action", "object", "permitted_by"):
        assert field in msg


def test_from_dict_rejects_non_dict_actor():
    payload = dict(VALID, actor="not-a-dict")
    with pytest.raises(ValueError, match="actor"):
        CausalRecord.from_dict(payload)


def test_from_dict_reports_actor_missing_field():
    payload = dict(VALID, actor={"pid": 1})  # missing uid
    with pytest.raises(ValueError, match="uid"):
        CausalRecord.from_dict(payload)
