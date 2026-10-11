"""Bounded consumer-ordering controls; not a truth or native ranking verdict."""

import hashlib
import importlib
import json
import os
import socket
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

SOURCE_SHA = "b7ad69afda6b6ed030347c66d48a13e4de9dec08"
JANUARY = "2026-01-15T12:00:00+00:00"
JUNE = "2026-06-15T12:00:00+00:00"
OCTOBER = "2026-10-11T12:00:00+00:00"
JAN_TEXT = "Synthetic January assertion: deployment region is North."
JUNE_TEXT = "Synthetic June assertion: deployment region is South."
VECTOR = [0.1, 0.2, 0.3]
CASES = []


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@pytest.fixture(scope="module", autouse=True)
def evidence_output():
    yield
    output = os.environ.get("MEM0_EVIDENCE_OUTPUT")
    if output:
        assert len(CASES) == 2
        report = {
            "schema": "mem0-7535-metadata-mutation-clock/1",
            "attempt_id": os.environ["MEM0_ATTEMPT_ID"],
            "source_sha": SOURCE_SHA,
            "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "fixed_mutation_clock": OCTOBER,
            "synthetic_fixed_input_scores": {"january": 0.6, "june": 0.9},
            "cases": CASES,
            "pass_count": len(CASES),
            "boundary": "Synthetic provider data; application timestamp sort, not native retrieval or truth ranking",
        }
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")


@pytest.fixture
def adapters(monkeypatch, tmp_path):
    attempts = []

    def deny_network(*args, **kwargs):
        attempts.append("socket connection or DNS attempt")
        raise AssertionError("Network is forbidden in this synthetic fixture")

    for target, name in [
        (socket.socket, "connect"),
        (socket.socket, "connect_ex"),
        (socket, "create_connection"),
        (socket, "getaddrinfo"),
    ]:
        monkeypatch.setattr(target, name, deny_network)
    monkeypatch.setenv("MEM0_TELEMETRY", "false")
    monkeypatch.setenv("MEM0_DIR", str(tmp_path / "mem0-home"))
    native = importlib.import_module("mem0.memory.main")
    source = Path(os.environ["MEM0_SOURCE"]).resolve()
    assert Path(native.__file__).resolve() == source / "mem0/memory/main.py"
    config_class = importlib.import_module("mem0.configs.base").MemoryConfig
    score_and_rank = importlib.import_module("mem0.utils.scoring").score_and_rank

    class FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            value = datetime.fromisoformat(OCTOBER)
            return value.astimezone(tz) if tz else value.replace(tzinfo=None)

    monkeypatch.setattr(native, "datetime", FixedClock)
    monkeypatch.setattr(native, "MEM0_TELEMETRY", False)
    monkeypatch.setattr(native, "capture_event", Mock())
    monkeypatch.setattr(native, "display_first_run_notice", Mock())
    monkeypatch.setattr(native, "display_first_run_notice_async", AsyncMock())
    rows = {}
    for identity, text, timestamp in [("january", JAN_TEXT, JANUARY), ("june", JUNE_TEXT, JUNE)]:
        rows[identity] = {
            "data": text,
            "hash": hashlib.md5(text.encode("utf-8")).hexdigest(),
            "created_at": timestamp,
            "updated_at": timestamp,
            "text_lemmatized": text,
            "user_id": "synthetic-user",
        }
    trace = []
    counts = {"get": 0, "embed": 0, "update": 0, "history_write": 0}

    def record(event):
        trace.append({"sequence": len(trace) + 1, "event": event, "counts": deepcopy(counts)})

    def get(vector_id):
        counts["get"] += 1
        record("provider_get")
        return SimpleNamespace(id=vector_id, payload=deepcopy(rows[vector_id]))

    def embed(text, memory_action):
        assert (text, memory_action) == (JAN_TEXT, "update")
        counts["embed"] += 1
        record("provider_embed_unchanged_text")
        return VECTOR[:]

    def update(vector_id, vector, payload):
        assert vector_id == "january" and vector == VECTOR
        counts["update"] += 1
        rows[vector_id] = deepcopy(payload)
        record("provider_update")

    store = Mock(get=Mock(side_effect=get), update=Mock(side_effect=update))
    llm = Mock()
    monkeypatch.setattr(native.EmbedderFactory, "create", Mock(return_value=Mock(embed=Mock(side_effect=embed))))
    monkeypatch.setattr(native.VectorStoreFactory, "create", Mock(return_value=store))
    monkeypatch.setattr(native.LlmFactory, "create", Mock(return_value=llm))

    def construct(asynchronous):
        config = config_class(history_db_path=str(tmp_path / "history.sqlite"))
        memory = (native.AsyncMemory if asynchronous else native.Memory)(config)
        real_add_history = memory.db.add_history

        def add_history(*args, **kwargs):
            real_add_history(*args, **kwargs)
            counts["history_write"] += 1
            record("native_sqlite_history_written")

        monkeypatch.setattr(memory.db, "add_history", add_history)
        return memory

    yield SimpleNamespace(
        rows=rows,
        counts=counts,
        trace=trace,
        record=record,
        construct=construct,
        scorer=score_and_rank,
        llm=llm,
        network_attempts=attempts,
        source=str(source),
    )
    assert attempts == []


def observe(adapter):
    rows = deepcopy(adapter.rows)
    app_order = sorted(rows, key=lambda identity: rows[identity]["updated_at"], reverse=True)
    # Fixed synthetic relevance inputs exercise the real scorer, not a native vector-search score claim.
    candidates = [
        {"id": identity, "score": score, "payload": rows[identity]}
        for identity, score in [("january", 0.6), ("june", 0.9)]
    ]
    ranked = adapter.scorer(candidates, {}, {}, threshold=0, top_k=2, explain=True)
    return {
        "rows": rows,
        "application_updated_at_order": app_order,
        "native_fixed_score_signature": [
            {key: item[key] for key in ("id", "score", "score_details")} for item in ranked
        ],
    }


def verify(adapter, before, after, result, history, api):
    assert result == {"message": "Memory updated successfully!"}
    for field in ("data", "hash", "created_at"):
        assert after["rows"]["january"][field] == before["rows"]["january"][field]
    assert after["rows"]["january"]["audit_tag"] == "metadata-only-review"
    assert after["rows"]["january"]["updated_at"] == OCTOBER
    assert datetime.fromisoformat(OCTOBER) > datetime.fromisoformat(JUNE)
    assert canonical_bytes(after["rows"]["june"]) == canonical_bytes(before["rows"]["june"])
    assert before["application_updated_at_order"] == ["june", "january"]
    assert after["application_updated_at_order"] == ["january", "june"]
    assert before["native_fixed_score_signature"] == after["native_fixed_score_signature"]
    assert [item["id"] for item in after["native_fixed_score_signature"]] == ["june", "january"]
    assert adapter.counts == {"get": 1, "embed": 1, "update": 1, "history_write": 1}
    assert adapter.llm.mock_calls == []
    assert len(history) == 1
    assert history[0]["old_memory"] == history[0]["new_memory"] == JAN_TEXT
    assert history[0]["event"] == "UPDATE"
    assert history[0]["created_at"] == JANUARY and history[0]["updated_at"] == OCTOBER
    assert [item["event"] for item in adapter.trace] == [
        "before_public_update",
        "provider_get",
        "provider_embed_unchanged_text",
        "provider_update",
        "native_sqlite_history_written",
        "public_update_returned",
    ]
    assert adapter.network_attempts == []
    CASES.append(
        {
            "case": api,
            "before": before,
            "after": after,
            "history": history,
            "adapter_counts": deepcopy(adapter.counts),
            "trace": deepcopy(adapter.trace),
            "network_attempts": [],
            "source_path": adapter.source,
            "assertions": "PASS_WITHIN_BOUND",
        }
    )


def test_sync_metadata_mutation_clock(adapters):
    memory = adapters.construct(False)
    try:
        before = observe(adapters)
        adapters.record("before_public_update")
        result = memory.update("january", metadata={"audit_tag": "metadata-only-review"})
        adapters.record("public_update_returned")
        verify(adapters, before, observe(adapters), result, memory.history("january"), "Memory.update")
    finally:
        memory.db.connection.close()


@pytest.mark.asyncio
async def test_async_metadata_mutation_clock(adapters):
    memory = adapters.construct(True)
    try:
        before = observe(adapters)
        adapters.record("before_public_update")
        result = await memory.update("january", metadata={"audit_tag": "metadata-only-review"})
        adapters.record("public_update_returned")
        verify(adapters, before, observe(adapters), result, await memory.history("january"), "AsyncMemory.update")
    finally:
        memory.db.connection.close()
