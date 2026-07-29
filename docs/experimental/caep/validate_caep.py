#!/usr/bin/env python3
"""Validate a CAEP record against JSON Schema and semantic CML invariants."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def semantic_errors(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    episode_id = record.get("episode_id")

    if episode_id in record.get("causal_parent_ids", []):
        errors.append("episode_id must not be its own causal parent")
    if episode_id in record.get("supersedes", []):
        errors.append("episode_id must not supersede itself")

    dispatch = (record.get("action") or {}).get("dispatch") or {}
    verification = record.get("verification") or {}

    if verification.get("independence") == "independent":
        verifier_ref = (verification.get("verifier") or {}).get("ref")
        executor_ref = (dispatch.get("executor") or {}).get("ref")
        if verifier_ref and executor_ref and verifier_ref == executor_ref:
            errors.append("independent verifier must differ from executor")

    postcondition_ids = [
        item.get("id")
        for item in record.get("expected_postconditions", [])
        if item.get("id")
    ]
    if len(postcondition_ids) != len(set(postcondition_ids)):
        errors.append("expected postcondition ids must be unique")

    results = [check.get("result") for check in verification.get("checks", [])]
    if verification.get("verdict") == "verified" and (
        not results or any(result != "pass" for result in results)
    ):
        errors.append("verified verdict requires one or more passing checks only")
    if verification.get("verdict") == "diverged" and "fail" not in results:
        errors.append("diverged verdict requires at least one failed check")

    time_data = record.get("time") or {}
    try:
        if parse_time(time_data["valid_time"]) > parse_time(time_data["recorded_time"]):
            errors.append("valid_time must not be later than recorded_time")
    except (KeyError, ValueError):
        pass

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("record", type=Path)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path(__file__).with_name("caep.schema.json"),
    )
    args = parser.parse_args()

    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    record = json.loads(args.record.read_text(encoding="utf-8"))

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    schema_errors = sorted(
        validator.iter_errors(record),
        key=lambda error: [str(part) for part in error.path],
    )

    messages = [
        f"schema: /{'/'.join(str(part) for part in error.path)}: {error.message}"
        for error in schema_errors
    ]
    messages.extend(f"semantic: {message}" for message in semantic_errors(record))

    if messages:
        print("INVALID")
        for message in messages:
            print(f"- {message}")
        return 1

    print("VALID")
    return 0


if __name__ == "__main__":
    sys.exit(main())
