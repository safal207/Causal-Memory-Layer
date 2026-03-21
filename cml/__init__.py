"""
cml — Causal Memory Layer Python SDK

Core package for recording, computing, and auditing causal chains.

Modules:
    record  — CausalRecord, Actor, load_jsonl
    ctag    — CTAG 16-bit computation (DOM, CLASS, GEN, LHINT, SEAL)
    chain   — Chain reconstruction and path queries
    audit   — Audit engine (R1–R4)
    report  — Report generation (Markdown, JSON, text)

Quick start:

    from cml import load_jsonl, AuditEngine, AuditConfig

    records = load_jsonl("causal.jsonl")
    engine  = AuditEngine()
    result  = engine.run(records)
    print(result.passed(), result.findings)
"""

__version__ = "0.4.0"

from .record import CausalRecord, Actor, Action, load_jsonl, records_to_index
from .ctag   import (
    DOM, CLASS, CTAGState,
    compute_ctag, decode_ctag, compute_lhint,
)
from .chain  import reconstruct_chain, has_path, find_root, group_by_pid
from .audit  import AuditEngine, AuditConfig, AuditResult, Finding, Severity
from .report import to_markdown, to_json, to_text

__all__ = [
    # record
    "CausalRecord", "Actor", "Action", "load_jsonl", "records_to_index",
    # ctag
    "DOM", "CLASS", "CTAGState", "compute_ctag", "decode_ctag", "compute_lhint",
    # chain
    "reconstruct_chain", "has_path", "find_root", "group_by_pid",
    # audit
    "AuditEngine", "AuditConfig", "AuditResult", "Finding", "Severity",
    # report
    "to_markdown", "to_json", "to_text",
]
