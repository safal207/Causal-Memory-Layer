#!/usr/bin/env python3
"""Thin protected entrypoint for the intrinsically strict reviewer fallback core."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

CORE_PATH = Path(__file__).with_name("reviewer_fallback.py")
CORE_SPEC = importlib.util.spec_from_file_location("cml_reviewer_fallback_core", CORE_PATH)
if CORE_SPEC is None or CORE_SPEC.loader is None:
    raise RuntimeError("cannot load reviewer fallback core")
core = importlib.util.module_from_spec(CORE_SPEC)
sys.modules[CORE_SPEC.name] = core
CORE_SPEC.loader.exec_module(core)

for _name in dir(core):
    if not _name.startswith("__"):
        globals()[_name] = getattr(core, _name)


def main() -> None:
    """Delegate CLI execution without altering core security behavior."""

    core.main()


if __name__ == "__main__":
    main()
