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


WRITE_SIDE_EFFECTS = {"local_write", "external_write", "destructive"}
ACCEPTED_STATUSES = {"verified", "recovered"}


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains duplicate keys."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    """Load strict JSON and reject ambiguous numeric or duplicate-key forms."""
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number: {value}")
        ),
    )


def parse_time(value: str) -> datetime:
    """Parse an offset-aware ISO 8601 timestamp."""
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
    """Compute the SHA-256 digest for CAEP JSON v1 canonical bytes."""
    return hashlib.sha256(canonical_record_bytes(record)).hexdigest()


def schema_errors(schema: dict[str, Any], record: Any) -> list[str]:
    """Return deterministic JSON Schema diagnostics for a candidate record."""
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(record),
        key=lambda error: [str(part) for part in error.path],
    )
    return [
        f"schema: /{'/'.join(str(part) for part in error.path)}: {error.message}"
        for error in errors
    ]


def _actor_ref(value: Any) -> str | None:
    """Return an actor reference from a schema-valid actor-shaped value."""
    if isinstance(value, dict):
        ref = value.get("ref")
        if isinstance(ref, str) and ref:
            return ref
    return None


def _parse_optional_time(
    value: Any,
    field_name: str,
    errors: list[str],
) -> datetime | None:
    """Parse an optional timestamp and append a deterministic error on failure."""
    if value is None:
        return None
    if not isinstance(value, str):
        errors.append(f"invalid {field_name}: expected string")
        return None
    try:
        return parse_time(value)
    except ValueError as exc:
        errors.append(f"invalid {field_name}: {exc}")
        return None


def semantic_errors(record: dict[str, Any]) -> list[str]:
    """Check cross-field CAEP invariants not expressible in JSON Schema."""
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

    status = record["status"]
    action = record.get("action") or {}
    dispatch = action.get("dispatch") or {}
    verification = record.get("verification") or {}

    if (
        status in ACCEPTED_STATUSES
        and verification.get("independence") != "independent"
    ):
        errors.append(
            f"record status {status} requires independent verification"
        )

    if verification.get("independence") == "independent":
        verifier_ref = _actor_ref(verification.get("verifier"))
        if verifier_ref is None:
            errors.append("independent verification requires verifier identity")
        else:
            excluded_refs = {
                ref
                for ref in (
                    _actor_ref(dispatch.get("executor")),
                    _actor_ref((record.get("decision") or {}).get("maker")),
                )
                if ref is not None
            }
            if verifier_ref in excluded_refs:
                errors.append(
                    "independent verifier must differ from executor and decision maker"
                )

    postconditions = record.get("expected_postconditions", [])
    postcondition_ids = [item["id"] for item in postconditions]
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
    if (
        verification.get("verdict") in {"verified", "diverged"}
        and uncovered_targets
    ):
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

    critical_ids = {
        item["id"]
        for item in postconditions
        if item.get("severity") == "critical"
    }
    side_effect = action.get("side_effect")
    if status in ACCEPTED_STATUSES and side_effect in WRITE_SIDE_EFFECTS:
        if not critical_ids:
            errors.append(
                "accepted write transitions require at least one critical postcondition"
            )
        check_results = {
            check.get("postcondition_id"): check.get("result")
            for check in checks
        }
        failed_critical = sorted(
            condition_id
            for condition_id in critical_ids
            if check_results.get(condition_id) != "pass"
        )
        if failed_critical:
            errors.append(
                "critical postconditions must pass for accepted transitions: "
                + ", ".join(failed_critical)
            )

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

    started_at = _parse_optional_time(
        dispatch.get("started_at"), "dispatch.started_at", errors
    )
    completed_at = _parse_optional_time(
        dispatch.get("completed_at"), "dispatch.completed_at", errors
    )
    observed_at = _parse_optional_time(
        (record.get("outcome") or {}).get("observed_at"),
        "outcome.observed_at",
        errors,
    )
    verified_at = _parse_optional_time(
        verification.get("verified_at"),
        "verification.verified_at",
        errors,
    )
    expires_at = _parse_optional_time(
        (record.get("authorization") or {}).get("expires_at"),
        "authorization.expires_at",
        errors,
    )

    if started_at and completed_at and started_at > completed_at:
        errors.append("dispatch.started_at must not be later than completed_at")
    if completed_at and observed_at and completed_at > observed_at:
        errors.append(
            "dispatch.completed_at must not be later than outcome.observed_at"
        )
    if observed_at and verified_at and observed_at > verified_at:
        errors.append(
            "outcome.observed_at must not be later than verification.verified_at"
        )
    if started_at and expires_at and started_at > expires_at:
        errors.append(
            "authorization must not expire before dispatch.started_at"
        )

    return errors


def validate_parent_bindings(
    record: dict[str, Any],
    parents: Iterable[dict[str, Any]],
) -> list[str]:
    """Verify supplied causal parents and their digest bindings."""
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

    unexpected_ids = sorted(set(parent_map) - set(expected_ids))
    if unexpected_ids:
        errors.append(
            "supplied parent records not declared by causal_parent_ids: "
            + ", ".join(unexpected_ids)
        )

    return errors


def validate_record(
    schema: dict[str, Any],
    record: Any,
    parents: Iterable[dict[str, Any]] = (),
) -> list[str]:
    """Validate one CAEP record and resolve every declared causal parent."""
    messages = schema_errors(schema, record)
    if messages:
        return messages
    assert isinstance(record, dict)
    messages.extend(semantic_errors(record))
    if not messages:
        messages.extend(validate_parent_bindings(record, parents))
    return messages


def main() -> int:
    """Run the CAEP validator command-line interface."""
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
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        DuplicateKeyError,
        ValueError,
    ) as exc:
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
