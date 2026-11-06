"""Regression checks for the fail-closed CML trust-root refresh API retry."""

from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/trust-root-refresh.yml"
PR_NUMBER = "282"
BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
MERGE_SHA = "c" * 40
REPOSITORY = "safal207/Causal-Memory-Layer"


def _script() -> str:
    """Read exactly the executed inline freshness script, not a test copy."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["refresh"]["steps"]
    step = next(
        item
        for item in steps
        if item.get("name") == "Reconfirm current pull request transition"
    )
    run = step["run"]
    prefix = "python3 - <<'PY'\n"
    assert run.startswith(prefix)
    source, sep, trailing = run[len(prefix) :].partition("\nPY")
    assert sep and not trailing.strip()
    return source + "\n"


def _pull(*, changed_base: bool = False) -> dict:
    return {
        "base": {"ref": "main", "sha": "d" * 40 if changed_base else BASE_SHA},
        "head": {
            "sha": HEAD_SHA,
            "repo": {"full_name": REPOSITORY},
        },
        "merge_commit_sha": MERGE_SHA,
    }


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.github.com/repos/" + REPOSITORY + "/pulls/" + PR_NUMBER,
        code,
        "synthetic failure",
        None,
        None,
    )


def _execute(monkeypatch, tmp_path: Path, responses: list, calls: list, delays: list) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("REPOSITORY", REPOSITORY)
    monkeypatch.setenv("PULL_NUMBER", PR_NUMBER)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "github-output.txt"))
    monkeypatch.setenv("BASE_REF", "main")
    monkeypatch.setenv("BASE_SHA", BASE_SHA)
    monkeypatch.setenv("HEAD_SHA", HEAD_SHA)
    monkeypatch.setenv("HEAD_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("MERGE_SHA", MERGE_SHA)
    items = iter(responses)

    def fake_urlopen(request, timeout):
        assert timeout == 30
        assert request.full_url.endswith("/pulls/" + PR_NUMBER)
        calls.append(request.full_url)
        try:
            result = next(items)
        except StopIteration:
            pytest.fail("more API requests than bounded retry budget")
        if isinstance(result, Exception):
            raise result
        return io.BytesIO(json.dumps(result).encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(time, "sleep", delays.append)
    exec(compile(_script(), str(WORKFLOW), "exec"), {"__name__": "__main__"})


@pytest.mark.parametrize("status", [429, 502, 503, 504])
def test_transient_http_failure_retries_and_reconfirms(
    monkeypatch, tmp_path: Path, status: int
) -> None:
    calls, delays = [], []
    _execute(monkeypatch, tmp_path, [_http_error(status), _pull()], calls, delays)
    assert len(calls) == 2
    assert delays == [1]
    assert (tmp_path / "github-output.txt").read_text() == "fresh=true\n"
    evidence = json.loads(
        (tmp_path / "artifacts/trust-refresh/transition-freshness.json").read_text()
    )
    assert evidence["fresh"] is True
    assert evidence["expected"] == evidence["observed"]


def test_exhausted_transient_failures_remain_fail_closed(
    monkeypatch, tmp_path: Path
) -> None:
    calls, delays = [], []
    with pytest.raises(urllib.error.HTTPError) as caught:
        _execute(
            monkeypatch,
            tmp_path,
            [_http_error(503), _http_error(503), _http_error(503)],
            calls,
            delays,
        )
    assert caught.value.code == 503
    assert len(calls) == 3
    assert delays == [1, 2]
    assert not (tmp_path / "github-output.txt").exists()
    assert not (
        tmp_path / "artifacts/trust-refresh/transition-freshness.json"
    ).exists()


def test_authentication_failure_is_not_retried(monkeypatch, tmp_path: Path) -> None:
    calls, delays = [], []
    with pytest.raises(urllib.error.HTTPError) as caught:
        _execute(monkeypatch, tmp_path, [_http_error(401)], calls, delays)
    assert caught.value.code == 401
    assert len(calls) == 1
    assert delays == []
    assert not (tmp_path / "github-output.txt").exists()


def test_transport_failure_retries(monkeypatch, tmp_path: Path) -> None:
    calls, delays = [], []
    _execute(
        monkeypatch,
        tmp_path,
        [urllib.error.URLError("temporary connection reset"), _pull()],
        calls,
        delays,
    )
    assert len(calls) == 2
    assert delays == [1]
    assert (tmp_path / "github-output.txt").read_text() == "fresh=true\n"


def test_real_transition_drift_still_denies_freshness(
    monkeypatch, tmp_path: Path
) -> None:
    calls, delays = [], []
    _execute(monkeypatch, tmp_path, [_http_error(503), _pull(changed_base=True)], calls, delays)
    evidence = json.loads(
        (tmp_path / "artifacts/trust-refresh/transition-freshness.json").read_text()
    )
    assert evidence["fresh"] is False
    assert evidence["observed"]["base_sha"] != evidence["expected"]["base_sha"]
    assert (tmp_path / "github-output.txt").read_text() == "fresh=false\n"
    assert len(calls) == 2
    assert delays == [1]
