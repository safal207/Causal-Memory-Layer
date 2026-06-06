from __future__ import annotations

from typing import Any


def extract_fixture_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a Cause Band fixture from either a fixture file or example sidecar.

    Some demo files wrap the experimental Cause Band fixture under
    `cause_band_sidecar` so the same JSON can describe a broader agent trace
    and still carry a runnable Cause Band payload.
    """
    sidecar = raw.get("cause_band_sidecar")
    if isinstance(sidecar, dict):
        return sidecar
    return raw
