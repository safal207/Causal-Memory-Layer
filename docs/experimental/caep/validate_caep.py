#!/usr/bin/env python3
"""Validate CAEP records, semantic invariants, digests, and causal parents."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator, FormatChecker


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains duplicate keys."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number: {value}")
        ),
    )


def parse_time(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return timestamp


def canonical_record_bytes(record: dict[str, Any]) -> bytes:
    """Return CAEP JSON v1 canonical bytes for digest verification."""
    canonical = copy.deepcopy(record)
    integrity = canonical.get("integrity")
    if isinstance(integrity, dict):
        integrity.pop("record_digest", None)
        integrity.pop("signature", None)
    return json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def compute_record_digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_record_bytes(record)).hexdigest()


def schema_errors(schema: dict[str, Any], record: Any) -> list[str]:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(record),
        key=lambda error: [str(part) for part in error.path],
    )
    return [
        f"schema: /{'/'.join(str(part) for part in error.path)}: {error.message}"
        for error in errors
    ]


def semantic_errors(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    episode_id = record["episode_id"]
    parent_ids = record.get("causal_parent_ids", [])
    supersedes = record.get("supersedes", [])

    if episode_id in parent_ids:
        errors.append("episode_id must not be its own causal parent")
    if episode_id in supersedes:
        errors.append("episode_id must not supersede itself")

    integrity = record["integrity"]
    parent_digests = integrity.get("parent_digests", {})
    missing_bindings = sorted(set(parent_ids) - set(parent_digests))
    extra_bindings = sorted(set(parent_digests) - set(parent_ids))
    if missing_bindings:
        errors.append(
            "missing parent digest bindings: " + ", ".join(missing_bindings)
        )
    if extra_bindings:
        errors.append(
            "parent digest bindings without matching causal parent ids: "
            + ", ".join(extra_bindings)
        )

    declared_digest = integrity["record_digest"]["value"].lower()
    computed_digest = compute_record_digest(record)
    if declared_digest != computed_digest:
        errors.append(
            f"record digest mismatch: declared {declared_digest}, "
            f"computed {computed_digest}"
        )

    dispatch = (record.get("action") or {}).get("dispatch") or {}
    verification = record.get("verification") or {}

    if verification.get("independence") == "independent":
        verifier = verification.get("verifier")
        if not isinstance(verifier, dict) or not verifier.get("ref"):
            errors.append("independent verification requires verifier identity")
        else:
            verifier_ref = verifier["ref"]
            executor_ref = (dispatch.get("executor") or {}).get("ref")
            if executor_ref and verifier_ref == executor_ref:
                errors.append("independent verifier must differ from executor")

    postcondition_ids = [
        item["id"] for item in record.get("expected_postconditions", [])
    ]
    if len(postcondition_ids) != len(set(postcondition_ids)):
        errors.append("expected postcondition ids must be unique")

    checks = verification.get("checks", [])
    check_targets = [check.get("postcondition_id") for check in checks]
    unknown_targets = sorted(set(check_targets) - set(postcondition_ids))
    uncovered_targets = sorted(set(postcondition_ids) - set(check_targets))
    if unknown_targets:
        errors.append(
            "verification checks reference undeclared postconditions: "
            + ", ".join(unknown_targets)
        )
    if verification.get("verdict") in {"verified", "diverged"} and uncovered_targets:
        errors.append(
            "declared postconditions lack verification checks: "
            + ", ".join(uncovered_targets)
        )

    results = [check.get("result") for check in checks]
    if verification.get("verdict") == "verified" and (
        not results or any(result != "pass" for result in results)
    ):
        errors.append("verified verdict requires one or more passing checks only")
    if verification.get("verdict") == "diverged" and "fail" not in results:
        errors.append("diverged verdict requires at least one failed check")

    status = record["status"]
    recovery = record.get("recovery") or {}
    if status == "recovered":
        if recovery.get("status") != "recovered":
            errors.append(
                "record status recovered requires recovery.status recovered"
            )
        if verification.get("verdict") != "verified":
            errors.append(
                "record status recovered requires verification.verdict verified"
            )
    if status == "contained" and recovery.get("status") != "contained":
        errors.append(
            "record status contained requires recovery.status contained"
        )

    try:
        valid_time = parse_time(record["time"]["valid_time"])
        recorded_time = parse_time(record["time"]["recorded_time"])
        if valid_time > recorded_time:
            errors.append("valid_time must not be later than recorded_time")
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"invalid record time: {exc}")

    return errors


def validate_parent_bindings(
    record: dict[str, Any],
    parents: Iterable[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    parent_map: dict[str, dict[str, Any]] = {}

    for parent in parents:
        parent_id = parent["episode_id"]
        if parent_id in parent_map:
            errors.append(f"duplicate supplied parent episode_id: {parent_id}")
        parent_map[parent_id] = parent

    expected_ids = record.get("causal_parent_ids", [])
    bindings = record["integrity"].get("parent_digests", {})

    for parent_id in expected_ids:
        parent = parent_map.get(parent_id)
        if parent is None:
            errors.append(f"missing supplied parent record: {parent_id}")
            continue
        computed = compute_record_digest(parent)
        parent_declared = parent["integrity"]["record_digest"]["value"].lower()
        expected = bindings[parent_id]["value"].lower()
        if parent_declared != computed:
            errors.append(
                f"parent {parent_id} has invalid record digest: "
                f"declared {parent_declared}, computed {computed}"
            )
        if expected != computed:
            errors.append(
                f"parent binding mismatch for {parent_id}: "
                f"expected {expected}, computed {computed}"
            )

    return errors


def validate_record(
    schema: dict[str, Any],
    record: Any,
    parents: Iterable[dict[str, Any]] = (),
) -> list[str]:
    messages = schema_errors(schema, record)
    if messages:
        return messages
    assert isinstance(record, dict)
    messages.extend(semantic_errors(record))
    if not messages:
        messages.extend(validate_parent_bindings(record, parents))
    return messages


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("record", type=Path)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path(__file__).with_name("caep.schema.json"),
    )
    parser.add_argument(
        "--parent",
        type=Path,
        action="append",
        default=[],
        help="Parent CAEP record; repeat for each causal parent.",
    )
    args = parser.parse_args()

    try:
        schema = load_json(args.schema)
        Draft202012Validator.check_schema(schema)
        record = load_json(args.record)
        parents = [load_json(path) for path in args.parent]
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError, ValueError) as exc:
        print("INVALID")
        print(f"- input: {exc}")
        return 1

    messages = validate_record(schema, record, parents)

    if messages:
        print("INVALID")
        for message in messages:
            print(f"- {message}")
        return 1

    print("VALID")
    return 0


if __name__ == "__main__":
    sys.exit(main())
