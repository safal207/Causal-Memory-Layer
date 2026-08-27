import json

import pytest

from cml.record import Action, Actor, CausalRecord, load_jsonl


def _record(read_id: str | None = "linux-read:10:11:123") -> CausalRecord:
    return CausalRecord(
        id="record-1",
        timestamp=123456,
        actor=Actor(pid=10, uid=1000),
        action=Action.READ,
        object={"fd": 3, "count": 8},
        permitted_by="parent_process_context",
        read_id=read_id,
    )


def test_read_id_survives_dict_round_trip():
    original = _record()

    restored = CausalRecord.from_dict(original.to_dict())

    assert restored.read_id == original.read_id
    assert restored.to_dict()["read_id"] == "linux-read:10:11:123"


def test_read_id_survives_jsonl_loader(tmp_path):
    path = tmp_path / "records.jsonl"
    path.write_text(_record().to_jsonl() + "\n", encoding="utf-8")

    loaded = load_jsonl(str(path))

    assert len(loaded) == 1
    assert loaded[0].read_id == "linux-read:10:11:123"


def test_legacy_record_without_read_id_remains_compatible():
    legacy = _record(read_id=None)

    payload = legacy.to_dict()
    restored = CausalRecord.from_dict(payload)

    assert "read_id" not in payload
    assert restored.read_id is None


def test_file_monitor_shape_does_not_drop_top_level_read_id():
    payload = {
        "id": "entry-record",
        "read_id": "linux-read:42:43:999",
        "timestamp": 999,
        "actor": {"pid": 42, "tid": 43, "uid": 1000, "comm": "reader"},
        "action": "read",
        "object": {"fd": 7, "count": 4, "boundary_started_ns": 999},
        "permitted_by": "unobserved_parent",
        "parent_cause": None,
    }

    restored = CausalRecord.from_dict(json.loads(json.dumps(payload)))

    assert restored.read_id == "linux-read:42:43:999"
    assert restored.action == Action.READ


def test_blank_read_id_fails_closed():
    with pytest.raises(ValueError, match="read_id must be a non-empty string"):
        _record(read_id="")
