"""
cml — Causal Memory Layer Python SDK

Core package for recording, computing, auditing, and routing causal trust evidence.

Modules:
    record                   — CausalRecord, Actor, load_jsonl
    ctag                     — CTAG 16-bit computation (DOM, CLASS, GEN, LHINT, SEAL)
    chain                    — Chain reconstruction and path queries
    audit                    — Audit engine (R1–R4)
    report                   — Report generation (Markdown, JSON, text)
    reviewer_router          — Provider/persona routing with explicit provenance
    reviewer_rubric_policy   — Executable rubric trust boundary
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("causal-memory-layer")
except PackageNotFoundError:  # not installed (editable source checkout)
    __version__ = "0.0.0+unknown"

from .record import CausalRecord, Actor, Action, load_jsonl, records_to_index
from .ctag import (
    DOM, CLASS, CTAGState,
    compute_ctag, decode_ctag, compute_lhint,
)
from .chain import reconstruct_chain, has_path, find_root, group_by_pid
from .audit import AuditEngine, AuditConfig, AuditResult, Finding, Severity, CustomRule
from .report import to_markdown, to_json, to_text

# The router module is loaded first so the policy module can reuse its public
# exception type without a circular import. Install the policy before exposing
# any reviewer classes: ReviewerProfile resolves _review_rubric from the module
# globals at construction time, including YAML-driven construction.
from . import reviewer_router as _reviewer_router
from .reviewer_rubric_policy import validate_reviewer_rubric as _validate_reviewer_rubric

_reviewer_router._review_rubric = _validate_reviewer_rubric

from .reviewer_router import (
    CandidateAssessment,
    EvidenceLevel,
    FallbackReason,
    NormalizedReviewFinding,
    ProviderStatus,
    ReviewRequest,
    ReviewerPersonaRouter,
    ReviewerProfile,
    ReviewerProvider,
    ReviewerRoutingError,
    RouteDecision,
)

__all__ = [
    # record
    "CausalRecord", "Actor", "Action", "load_jsonl", "records_to_index",
    # ctag
    "DOM", "CLASS", "CTAGState", "compute_ctag", "decode_ctag", "compute_lhint",
    # chain
    "reconstruct_chain", "has_path", "find_root", "group_by_pid",
    # audit
    "AuditEngine", "AuditConfig", "AuditResult", "Finding", "Severity", "CustomRule",
    # report
    "to_markdown", "to_json", "to_text",
    # reviewer router
    "CandidateAssessment", "EvidenceLevel", "FallbackReason",
    "NormalizedReviewFinding", "ProviderStatus", "ReviewRequest",
    "ReviewerPersonaRouter", "ReviewerProfile", "ReviewerProvider",
    "ReviewerRoutingError", "RouteDecision",
]
