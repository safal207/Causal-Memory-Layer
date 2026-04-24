import subprocess
import sys


def test_cli_audit_fails_closed_on_invalid_jsonl(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text(
        '{"id":"x","timestamp":1,"actor":{"pid":1,"uid":1},"action":"exec","object":"/bin/sh","permitted_by":"root_event:init"}\nnot-json\n',
        encoding='utf-8',
    )

    result = subprocess.run(
        [sys.executable, '-m', 'cli.main', 'audit', str(bad)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Failed to parse log" in result.stderr


def test_cli_chain_fails_closed_on_malformed_record(tmp_path):
    bad = tmp_path / "bad_record.jsonl"
    bad.write_text(
        '{"id":"x","timestamp":1,"actor":{"pid":1},"action":"exec","object":"/bin/sh","permitted_by":"root_event:init"}\n',
        encoding='utf-8',
    )

    result = subprocess.run(
        [sys.executable, '-m', 'cli.main', 'chain', str(bad), 'x'],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Failed to parse log" in result.stderr


def test_cli_audit_rejects_boolean_integer_fields(tmp_path):
    bad = tmp_path / "bad_bool_ints.jsonl"
    bad.write_text(
        "{\"id\":\"x\",\"timestamp\":true,\"actor\":{\"pid\":true,\"uid\":false},\"action\":\"exec\",\"object\":\"/bin/sh\",\"permitted_by\":\"root_event:init\"}\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "-m", "cli.main", "audit", str(bad)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Failed to parse log" in result.stderr


def test_cli_audit_rejects_empty_parent_cause(tmp_path):
    bad = tmp_path / "bad_empty_parent.jsonl"
    bad.write_text(
        "{\"id\":\"x\",\"timestamp\":1,\"actor\":{\"pid\":1,\"uid\":1},\"action\":\"exec\",\"object\":\"/bin/sh\",\"permitted_by\":\"root_event:init\",\"parent_cause\":\"   \"}\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "-m", "cli.main", "audit", str(bad)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Failed to parse log" in result.stderr
