"""
cml — Causal Memory Layer Python SDK

Core package for recording, computing, and auditing causal chains.

Modules:
    record  — CausalRecord, Actor, load_jsonl
    ctag    — CTAG 16-bit computation (DOM, CLASS, GEN, LHINT, SEAL)
    chain   — Chain reconstruction and path queries
    audit   — Audit engine (R1–R4)
    three_record_audit — trustworthy-transition causal join validation
    report  — Report generation (Markdown, JSON, text)

Quick start:

    from cml import load_jsonl, AuditEngine, AuditConfig

    records = load_jsonl("causal.jsonl")
    engine  = AuditEngine()
    result  = engine.run(records)
    print(result.passed(), result.findings)
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("causal-memory-layer")
except PackageNotFoundError:  # not installed (editable source checkout)
    __version__ = "0.0.0+unknown"

from .record import CausalRecord, Actor, Action, load_jsonl, records_to_index
from .ctag   import (
    DOM, CLASS, CTAGState,
    compute_ctag, decode_ctag, compute_lhint,
)
from .chain  import reconstruct_chain, has_path, find_root, group_by_pid
from .audit  import AuditEngine, AuditConfig, AuditResult, Finding, Severity, CustomRule
from .three_record_audit import (
    CausalFinding,
    FindingCode,
    ThreeRecordAuditError,
    audit_three_record_transition,
    canonical_json,
    record_ref,
    wrap_record,
)
from .report import to_markdown, to_json, to_text

__all__ = [
    # record
    "CausalRecord", "Actor", "Action", "load_jsonl", "records_to_index",
    # ctag
    "DOM", "CLASS", "CTAGState", "compute_ctag", "decode_ctag", "compute_lhint",
    # chain
    "reconstruct_chain", "has_path", "find_root", "group_by_pid",
    # audit
    "AuditEngine", "AuditConfig", "AuditResult", "Finding", "Severity", "CustomRule",
    # trustworthy-transition causal audit
    "CausalFinding", "FindingCode", "ThreeRecordAuditError",
    "audit_three_record_transition", "canonical_json", "record_ref", "wrap_record",
    # report
    "to_markdown", "to_json", "to_text",
]
