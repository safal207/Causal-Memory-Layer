"""
CML CLI entry point.

Usage:
  python -m cli.main audit <file.jsonl> [--format json|text]
  python -m cli.main chain <file.jsonl> <record_id>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _validate_raw_record(raw: dict, line_no: int) -> None:
    required = ("id", "timestamp", "actor", "action", "object", "permitted_by")
    missing = [key for key in required if key not in raw]
    if missing:
        raise ValueError(f"Line {line_no}: missing required keys: {missing}")
    if not isinstance(raw["id"], str) or not raw["id"].strip():
        raise ValueError(f"Line {line_no}: field 'id' must be a non-empty string")
    if not isinstance(raw["timestamp"], int):
        raise ValueError(f"Line {line_no}: field 'timestamp' must be an integer")
    if not isinstance(raw["action"], str) or not raw["action"].strip():
        raise ValueError(f"Line {line_no}: field 'action' must be a non-empty string")
    if not isinstance(raw["permitted_by"], str) or not raw["permitted_by"].strip():
        raise ValueError(f"Line {line_no}: field 'permitted_by' must be a non-empty string")
    actor = raw["actor"]
    if not isinstance(actor, dict):
        raise ValueError(f"Line {line_no}: field 'actor' must be an object")
    if not isinstance(actor.get("pid"), int) or not isinstance(actor.get("uid"), int):
        raise ValueError(f"Line {line_no}: actor.pid and actor.uid must be integers")
    parent = raw.get("parent_cause")
    if parent is not None and not isinstance(parent, str):
        raise ValueError(f"Line {line_no}: field 'parent_cause' must be a string or null")


def _load_jsonl(file_path: str) -> list[dict]:
    records = []
    with open(file_path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Line {line_no}: invalid JSON ({exc})") from exc
            if not isinstance(raw, dict):
                raise ValueError(f"Line {line_no}: each JSONL entry must be an object")
            _validate_raw_record(raw, line_no)
            records.append(raw)
    return records


def _cmd_audit(args: argparse.Namespace) -> None:
    from cli.audit import audit

    file_path = args.file
    if not Path(file_path).exists():
        print(f"[ERROR] File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    try:
        records = _load_jsonl(file_path)
    except ValueError as exc:
        print(f"[ERROR] Failed to parse log: {exc}", file=sys.stderr)
        sys.exit(1)
    result = audit(records)
    result["file"] = file_path

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        s = result["summary"]
        status = "PASSED" if s["passed"] else "FAILED"
        print(f"CML Audit: {status}")
        print(f"  File : {file_path}")
        print(f"  Total: {s['total']}  OK: {s['ok']}  WARN: {s['warn']}  FAIL: {s['fail']}")
        for f in result["findings"]:
            if f["severity"] != "OK":
                loc = f"line {f['line']}" if f.get("line") else "?"
                print(f"  [{f['severity']}] {f['code']} @ {f['record_id']} ({loc})")
                print(f"        {f['message']}")


def _cmd_chain(args: argparse.Namespace) -> None:
    from cli.chain import reconstruct_chain

    file_path = args.file
    if not Path(file_path).exists():
        print(f"[ERROR] File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    try:
        records = _load_jsonl(file_path)
    except ValueError as exc:
        print(f"[ERROR] Failed to parse log: {exc}", file=sys.stderr)
        sys.exit(1)
    result = reconstruct_chain(records, args.record_id)
    print(json.dumps(result, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cml",
        description="Causal Memory Layer CLI — audit and chain inspection",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    audit_p = sub.add_parser("audit", help="Audit a JSONL causal log against CML rules")
    audit_p.add_argument("file", help="Path to .jsonl causal log")
    audit_p.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    chain_p = sub.add_parser("chain", help="Reconstruct causal chain for a record")
    chain_p.add_argument("file", help="Path to .jsonl causal log")
    chain_p.add_argument("record_id", help="ID of the record to trace")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "audit":
        _cmd_audit(args)
    elif args.command == "chain":
        _cmd_chain(args)


if __name__ == "__main__":
    main()
