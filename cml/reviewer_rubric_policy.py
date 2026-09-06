"""Fail-closed policy for executable reviewer rubric text.

The router implementation owns routing and provenance. This module owns the
narrow language boundary for configurable rubric items so ordinary technical
output verbs are not confused with reviewer identity or authority grants.
"""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence

from .reviewer_router import ReviewerRoutingError

_NEUTRAL_REVIEW_VERBS = frozenset(
    {
        "analyze",
        "assess",
        "audit",
        "check",
        "evaluate",
        "examine",
        "inspect",
        "review",
        "test",
        "verify",
    }
)

# These verbs are authority conclusions by themselves. They are never valid
# executable review criteria, even when the rubric omits words such as merge.
_STRICT_AUTHORITY_ACTIONS = frozenset(
    {
        "accept",
        "accepted",
        "accepting",
        "allow",
        "allowed",
        "allowing",
        "approve",
        "approved",
        "approving",
        "authorize",
        "authorized",
        "authorizing",
        "certify",
        "certified",
        "certifying",
        "endorse",
        "endorsed",
        "endorsing",
        "grant",
        "granted",
        "granting",
        "permit",
        "permitted",
        "permitting",
        "recommend",
        "recommended",
        "recommending",
        "sign",
        "signed",
        "signing",
    }
)

# These are ordinary technical output verbs. They become unsafe only when the
# same item asks them to emit an identity, approval, verdict, or merge result.
_CONTEXTUAL_OUTPUT_ACTIONS = frozenset(
    {
        "emit",
        "emitted",
        "emitting",
        "issue",
        "issued",
        "issuing",
        "produce",
        "produced",
        "producing",
        "provide",
        "provided",
        "providing",
        "publish",
        "published",
        "publishing",
        "report",
        "reported",
        "reporting",
        "return",
        "returned",
        "returning",
        "submit",
        "submitted",
        "submitting",
        "use",
        "used",
        "using",
    }
)

_IDENTITY_ACTIONS = frozenset(
    {
        "act",
        "acting",
        "adopt",
        "adopted",
        "adopting",
        "are",
        "assert",
        "be",
        "become",
        "claim",
        "declare",
        "identify",
        "impersonate",
        "is",
        "label",
        "mark",
        "pretend",
        "represent",
        "serve",
        "serving",
        "treat",
    }
)

_IDENTITY_TERMS = frozenset(
    {"approval", "authority", "identity", "native", "reviewer", "status", "verdict"}
)
_AUTHORITY_TERMS = frozenset(
    {"approval", "authority", "permission", "right", "rights"}
)
_MERGE_TERMS = frozenset({"merge", "merged", "merging"})
_SENSITIVE_TERMS = _IDENTITY_TERMS | _AUTHORITY_TERMS | _MERGE_TERMS
_PROTECTED_CONCLUSION_TARGETS = _SENSITIVE_TERMS
# Adoption is about assuming reviewer identity or authority. The word `merge`
# and a standalone `requested` describe ordinary technical work and are not
# adoption targets by themselves.
_ADOPTION_TARGETS = _IDENTITY_TERMS | _AUTHORITY_TERMS

_SAFE_SUBJECT_MARKERS = frozenset(
    {
        "behavior",
        "behaviour",
        "boundaries",
        "boundary",
        "bypass",
        "bypasses",
        "check",
        "checks",
        "code",
        "condition",
        "conditions",
        "correctness",
        "enforcement",
        "failure",
        "failures",
        "flow",
        "flows",
        "focus",
        "guard",
        "guards",
        "handling",
        "implementation",
        "logic",
        "output",
        "outputs",
        "path",
        "paths",
        "performance",
        "policies",
        "policy",
        "propagation",
        "race",
        "races",
        "reliability",
        "remediation",
        "result",
        "results",
        "routing",
        "rule",
        "rules",
        "scheduling",
        "security",
        "selection",
        "state",
        "states",
        "test",
        "tests",
        "transition",
        "transitions",
        "validation",
    }
)


def _printable_items(value: object) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ReviewerRoutingError("profile rubric must be a list")
    items: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise ReviewerRoutingError("profile rubric must be text")
        item = raw.strip()
        if not item or any(ord(char) < 32 for char in item):
            raise ReviewerRoutingError("profile rubric must be printable text")
        items.append(item)
    if not items:
        raise ReviewerRoutingError("profile rubric must not be empty")
    return tuple(items)


def _tokens(item: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", item)
    if any(
        unicodedata.category(char) in {"Cc", "Cf", "Cs"}
        for char in normalized
    ):
        raise ReviewerRoutingError(
            "profile rubric cannot contain hidden Unicode control characters"
        )
    if any(ord(char) > 127 for char in normalized):
        raise ReviewerRoutingError(
            "profile rubric cannot contain non-ASCII letters or combining marks, "
            "punctuation, or symbols"
        )
    return tuple(re.findall(r"[a-z0-9]+", normalized.casefold()))


def _contains_phrase(tokens: tuple[str, ...], phrase: tuple[str, ...]) -> bool:
    width = len(phrase)
    return any(
        tokens[index : index + width] == phrase
        for index in range(len(tokens) - width + 1)
    )


def _has_adoption_relationship(tokens: tuple[str, ...]) -> bool:
    if _contains_phrase(tokens, ("on", "behalf", "of")):
        return True
    if _contains_phrase(tokens, ("in", "the", "identity", "of")):
        return True
    if _contains_phrase(tokens, ("in", "identity", "of")):
        return True
    for index, token in enumerate(tokens):
        if token not in {"as", "under", "with"}:
            continue
        following = frozenset(tokens[index + 1 :])
        if following & _ADOPTION_TARGETS:
            return True
    return False


def _sensitive_terms_have_technical_context(tokens: tuple[str, ...]) -> bool:
    for index, token in enumerate(tokens):
        if token not in _SENSITIVE_TERMS:
            continue
        lower = max(0, index - 2)
        upper = min(len(tokens), index + 5)
        if not frozenset(tokens[lower:upper]) & _SAFE_SUBJECT_MARKERS:
            return False
    return True


def validate_reviewer_rubric(value: object) -> tuple[str, ...]:
    """Return normalized rubric items or fail closed on authority injection."""
    items = _printable_items(value)
    for item in items:
        tokens = _tokens(item)
        token_set = frozenset(tokens)
        first_alpha = next((token for token in tokens if token.isalpha()), "")
        neutral_review = first_alpha in _NEUTRAL_REVIEW_VERBS
        strict_authority = bool(token_set & _STRICT_AUTHORITY_ACTIONS)
        contextual_output = bool(token_set & _CONTEXTUAL_OUTPUT_ACTIONS)
        protected_target = bool(token_set & _PROTECTED_CONCLUSION_TARGETS)
        sensitive = bool(token_set & _SENSITIVE_TERMS)
        identity_action = bool(token_set & _IDENTITY_ACTIONS)

        if strict_authority or (contextual_output and protected_target):
            raise ReviewerRoutingError(
                "profile rubric cannot define reviewer identity, native approval, "
                "or merge authority; sensitive terms must use the safe technical "
                "review-subject grammar"
            )

        safe_sensitive_subject = (
            neutral_review
            and _sensitive_terms_have_technical_context(tokens)
            and not identity_action
            and not _has_adoption_relationship(tokens)
        )
        if sensitive and not safe_sensitive_subject:
            raise ReviewerRoutingError(
                "profile rubric cannot define reviewer identity, native approval, "
                "or merge authority; sensitive terms must use the safe technical "
                "review-subject grammar"
            )
    return items
