#!/usr/bin/env python3
"""
cml — Causal Memory Layer CLI

Usage:
    cml audit   <log.jsonl> [--config FILE] [--format text|json|markdown]
    cml chain   <log.jsonl> <record_id>
    cml validate <log.jsonl>
    cml ctag    --dom DOM --class CLASS --gen GEN --parent PARENT_ID
    cml decode  <ctag_hex>
    cml report  <log.jsonl> [--output FILE] [--config FILE]
"""

import json
import sys
import os
import argparse

# Allow running as a script without installing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cml import (
    load_jsonl, records_to_index,
    AuditEngine, AuditConfig,
    reconstruct_chain, find_root,
    compute_ctag, decode_ctag, DOM, CLASS,
    to_markdown, to_json, to_text,
)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

def cmd_audit(args):
    records = load_jsonl(args.log)
    cfg = AuditConfig.from_yaml(args.config) if args.config else AuditConfig()
    engine = AuditEngine(cfg)
    result = engine.run(records)

    fmt = args.format or "text"
    if fmt == "json":
        print(to_json(result))
    elif fmt == "markdown":
        index = records_to_index(records)
        print(to_markdown(result, log_path=args.log, index=index))
    else:
        print(to_text(result))

    sys.exit(0 if result.passed() else 1)


# ---------------------------------------------------------------------------
# chain
# ---------------------------------------------------------------------------

def cmd_chain(args):
    records = load_jsonl(args.log)
    index = records_to_index(records)

    if args.record_id not in index:
        print(f"Error: record '{args.record_id}' not found.", file=sys.stderr)
        sys.exit(1)

    chain = reconstruct_chain(args.record_id, index)
    print(f"Chain for {args.record_id} ({len(chain)} records, root-first):\n")
    for i, r in enumerate(chain):
        connector = "  " if i == 0 else "→ "
        obj = r.object if isinstance(r.object, str) else json.dumps(r.object)
        print(
            f"{connector}[{r.id[:8]}] ts={r.timestamp} "
            f"action={r.action:<8s} obj={obj!r:40s} "
            f"permitted_by={r.permitted_by}"
        )


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

def cmd_validate(args):
    records = load_jsonl(args.log)
    cfg = AuditConfig()
    engine = AuditEngine(cfg)
    result = engine.run(records)

    print(f"Records:  {result.total}")
    print(f"Failures: {result.failures}")
    print(f"Warnings: {result.warnings}")
    print(f"Status:   {'PASS' if result.passed() else 'FAIL'}")
    sys.exit(0 if result.passed() else 1)


# ---------------------------------------------------------------------------
# ctag
# ---------------------------------------------------------------------------

def cmd_ctag(args):
    try:
        dom_val = int(args.dom) if args.dom.isdigit() else DOM.from_name(args.dom)
    except (KeyError, ValueError):
        print(f"Unknown DOM: {args.dom}", file=sys.stderr)
        sys.exit(1)

    try:
        cls_val = int(args.cls) if args.cls.isdigit() else CLASS.from_name(args.cls)
    except (KeyError, ValueError):
        print(f"Unknown CLASS: {args.cls}", file=sys.stderr)
        sys.exit(1)

    gen_val = int(args.gen)
    parent  = args.parent if args.parent and args.parent.lower() != "null" else None
    seal    = args.seal

    ctag = compute_ctag(dom_val, cls_val, gen_val, parent, seal)
    decoded = decode_ctag(ctag)
    print(json.dumps(decoded, indent=2))


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------

def cmd_decode(args):
    val = int(args.ctag_hex.strip(), 16)
    decoded = decode_ctag(val)
    print(json.dumps(decoded, indent=2))


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def cmd_report(args):
    records = load_jsonl(args.log)
    cfg = AuditConfig.from_yaml(args.config) if args.config else AuditConfig()
    engine = AuditEngine(cfg)
    result = engine.run(records)
    index = records_to_index(records)

    md = to_markdown(result, log_path=args.log, index=index)

    if args.output:
        with open(args.output, "w") as f:
            f.write(md)
        print(f"Report written to {args.output}")
    else:
        print(md)


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cml",
        description="Causal Memory Layer — CLI tool",
    )
    parser.add_argument("--version", action="version", version="cml 0.4.0")
    sub = parser.add_subparsers(dest="command", required=True)

    # audit
    p_audit = sub.add_parser("audit", help="Run causal audit on a log file")
    p_audit.add_argument("log", help="Path to JSONL causal log")
    p_audit.add_argument("--config", help="Audit config YAML (optional)")
    p_audit.add_argument(
        "--format", choices=["text", "json", "markdown"], default="text",
        help="Output format (default: text)"
    )
    p_audit.set_defaults(func=cmd_audit)

    # chain
    p_chain = sub.add_parser("chain", help="Reconstruct causal chain for a record")
    p_chain.add_argument("log", help="Path to JSONL causal log")
    p_chain.add_argument("record_id", help="Record ID to trace")
    p_chain.set_defaults(func=cmd_chain)

    # validate
    p_val = sub.add_parser("validate", help="Quick pass/fail validation")
    p_val.add_argument("log", help="Path to JSONL causal log")
    p_val.set_defaults(func=cmd_validate)

    # ctag
    p_ctag = sub.add_parser("ctag", help="Compute a 16-bit CTAG value")
    p_ctag.add_argument("--dom",    required=True, help="DOM name or int (e.g. USER or 4)")
    p_ctag.add_argument("--class",  dest="cls", required=True,
                        help="CLASS name or int (e.g. EXEC or 3)")
    p_ctag.add_argument("--gen",    required=True, type=int, help="GEN epoch (0-15)")
    p_ctag.add_argument("--parent", default=None, help="Parent cause UUID or null")
    p_ctag.add_argument("--seal",   action="store_true", help="Set SEAL bit")
    p_ctag.set_defaults(func=cmd_ctag)

    # decode
    p_dec = sub.add_parser("decode", help="Decode a hex CTAG value")
    p_dec.add_argument("ctag_hex", help="16-bit CTAG as hex (e.g. 0x48E2)")
    p_dec.set_defaults(func=cmd_decode)

    # report
    p_rep = sub.add_parser("report", help="Generate Markdown audit report")
    p_rep.add_argument("log", help="Path to JSONL causal log")
    p_rep.add_argument("--config", help="Audit config YAML (optional)")
    p_rep.add_argument("--output", "-o", help="Write report to file")
    p_rep.set_defaults(func=cmd_report)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
