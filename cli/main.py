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


def _load_jsonl(file_path: str) -> list[dict]:
    records = []
    with open(file_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    print(f"[WARN] Skipping invalid JSON line: {exc}", file=sys.stderr)
    return records


def _cmd_audit(args: argparse.Namespace) -> None:
    from cli.audit import audit

    file_path = args.file
    if not Path(file_path).exists():
        print(f"[ERROR] File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    records = _load_jsonl(file_path)
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

    records = _load_jsonl(file_path)
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
