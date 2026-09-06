from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    """Read a UTF-8 JSON document."""
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    """Write deterministic, reviewable UTF-8 JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def sha256_json(value: Any) -> str:
    """Hash deterministic compact JSON bytes."""
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
