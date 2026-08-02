from __future__ import annotations

import sys
import types
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1] / "hackathons" / "liminal-recall"
sys.path.insert(0, str(APP_ROOT))

import app.store as store_module
from app.store import CockroachMemoryStore


def _install_fake_psycopg(monkeypatch) -> dict[str, object]:
    calls: dict[str, object] = {}

    class FakePsycopg:
        @staticmethod
        def connect(database_url: str, **kwargs: object) -> object:
            calls["database_url"] = database_url
            calls.update(kwargs)
            return object()

    fake_psycopg = types.ModuleType("psycopg")
    fake_psycopg.connect = FakePsycopg.connect  # type: ignore[attr-defined]
    fake_rows = types.ModuleType("psycopg.rows")
    fake_rows.dict_row = object()
    monkeypatch.setitem(sys.modules, "psycopg", fake_psycopg)
    monkeypatch.setitem(sys.modules, "psycopg.rows", fake_rows)
    return calls


def test_connect_uses_bundled_trust_store_for_verify_full_urls(monkeypatch) -> None:
    calls = _install_fake_psycopg(monkeypatch)
    database_url = (
        "postgresql://synthetic-user:synthetic-password"
        "@db.invalid/db?sslmode=verify-full"
    )

    CockroachMemoryStore(database_url)._connect()

    assert calls["database_url"] == database_url
    expected_cert = Path(store_module.__file__).with_name("cockroach-root.crt")
    assert calls["sslrootcert"] == str(expected_cert)
    assert "sslmode" not in calls
    assert expected_cert.is_file()
    assert calls["connect_timeout"] == 8
    assert calls["application_name"] == "liminal-recall"


def test_connect_defaults_to_verify_full_when_url_omits_sslmode(monkeypatch) -> None:
    calls = _install_fake_psycopg(monkeypatch)
    database_url = "postgresql://synthetic-user:synthetic-password@db.invalid/db"

    CockroachMemoryStore(database_url)._connect()

    assert calls["database_url"] == database_url
    assert calls["sslmode"] == "verify-full"
    expected_cert = Path(store_module.__file__).with_name("cockroach-root.crt")
    assert calls["sslrootcert"] == str(expected_cert)
