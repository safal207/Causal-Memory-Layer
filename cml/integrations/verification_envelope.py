"""Dependency-free cross-system verification envelope primitives.

The canonicalization profile is deliberately narrower than full RFC 8785 JCS.
It accepts only the JSON subset for which Python's deterministic encoding is
byte-compatible with JCS: printable ASCII strings/keys, safe integers, booleans,
null, arrays, and objects. Full-JCS interoperability remains an external vector
test.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any


CANONICALIZATION_PROFILE = "rfc8785-jcs-ascii-integer-subset-v0.1"
MAX_SAFE_INTEGER = (2**53) - 1
FRESHNESS_RANK = {"issuance": 0, "consumption": 1, "execution": 2}
EXECUTION_BINDINGS = {"external", "attested"}


def _non_empty(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _validate_ascii(value: str, *, name: str) -> None:
    _non_empty(name, value)
    if not value.isascii():
        raise ValueError(f"{name} must be ASCII in {CANONICALIZATION_PROFILE}")
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
        raise ValueError(f"{name} must contain only printable ASCII characters")


def _validate_sha256_hex(name: str, value: str) -> None:
    _non_empty(name, value)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def _validate_canonical_subset(value: Any, *, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"{path} integer exceeds interoperable safe range")
        return
    if isinstance(value, float):
        raise ValueError(f"{path} floats are outside {CANONICALIZATION_PROFILE}")
    if isinstance(value, str):
        if not value.isascii():
            raise ValueError(f"{path} string must be ASCII")
        if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
            raise ValueError(f"{path} string must contain only printable ASCII characters")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_canonical_subset(item, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} object keys must be strings")
            _validate_ascii(key, name=f"{path} key")
            _validate_canonical_subset(item, path=f"{path}.{key}")
        return
    raise ValueError(f"{path} contains unsupported JSON type {type(value).__name__}")


def canonicalize_verification_content(content: dict[str, Any]) -> bytes:
    """Return canonical bytes for the frozen JCS-compatible subset."""

    if not isinstance(content, dict):
        raise TypeError("bound content must be a JSON object")
    _validate_canonical_subset(content)
    return json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256(content: dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize_verification_content(content)).hexdigest()


def content_commitment(content: dict[str, Any]) -> str:
    """Return SHA-256 over canonical bound-content bytes."""

    return _sha256(content)


def envelope_binding_payload(
    *,
    occurrence_id: str,
    content_commitment_value: str,
    commitment_scope: tuple[str, ...],
    canonicalization_profile: str,
    fresh_through: str,
    execution_binding: str,
    requires_use_time_revalidation: bool,
) -> dict[str, Any]:
    """Return the semantic payload that links occurrence, content, and disclosures."""

    return {
        "occurrence_id": occurrence_id,
        "content_commitment": content_commitment_value,
        "commitment_scope": list(commitment_scope),
        "canonicalization_profile": canonicalization_profile,
        "fresh_through": fresh_through,
        "execution_binding": execution_binding,
        "requires_use_time_revalidation": requires_use_time_revalidation,
    }


def compute_envelope_commitment(
    *,
    occurrence_id: str,
    content_commitment_value: str,
    commitment_scope: tuple[str, ...],
    canonicalization_profile: str,
    fresh_through: str,
    execution_binding: str,
    requires_use_time_revalidation: bool,
) -> str:
    """Bind occurrence identity to the content commitment and capability disclosure."""

    return _sha256(
        envelope_binding_payload(
            occurrence_id=occurrence_id,
            content_commitment_value=content_commitment_value,
            commitment_scope=commitment_scope,
            canonicalization_profile=canonicalization_profile,
            fresh_through=fresh_through,
            execution_binding=execution_binding,
            requires_use_time_revalidation=requires_use_time_revalidation,
        )
    )


@dataclass(frozen=True)
class VerificationEnvelope:
    occurrence_id: str
    content_commitment: str
    envelope_commitment: str
    commitment_scope: tuple[str, ...]
    canonicalization_profile: str
    fresh_through: str
    execution_binding: str
    requires_use_time_revalidation: bool

    def __post_init__(self) -> None:
        _non_empty("occurrence_id", self.occurrence_id)
        _validate_sha256_hex("content_commitment", self.content_commitment)
        _validate_sha256_hex("envelope_commitment", self.envelope_commitment)
        if not self.commitment_scope:
            raise ValueError("commitment_scope must not be empty")
        if tuple(sorted(set(self.commitment_scope))) != self.commitment_scope:
            raise ValueError("commitment_scope must be sorted and unique")
        for field in self.commitment_scope:
            _validate_ascii(field, name="commitment_scope field")
        if self.canonicalization_profile != CANONICALIZATION_PROFILE:
            raise ValueError("unsupported canonicalization_profile")
        if self.fresh_through not in FRESHNESS_RANK:
            raise ValueError("fresh_through must be issuance, consumption, or execution")
        if self.execution_binding not in EXECUTION_BINDINGS:
            raise ValueError("execution_binding must be external or attested")
        if self.fresh_through == "execution" and self.execution_binding != "attested":
            raise ValueError("fresh_through=execution requires execution_binding=attested")
        expected_revalidation = self.fresh_through != "execution"
        if self.requires_use_time_revalidation is not expected_revalidation:
            raise ValueError("requires_use_time_revalidation contradicts fresh_through")


@dataclass(frozen=True)
class VerificationEnvelopeValidation:
    valid: bool
    reasons: tuple[str, ...]
    reproduced_content_commitment: str
    reproduced_envelope_commitment: str
    execution_binding: str
    fresh_through: str
    requires_use_time_revalidation: bool


def issue_verification_envelope(
    *,
    occurrence_id: str,
    bound_content: dict[str, Any],
    commitment_scope: tuple[str, ...],
    fresh_through: str,
    execution_binding: str,
) -> VerificationEnvelope:
    """Issue one envelope whose scope exactly names the bound top-level fields."""

    _non_empty("occurrence_id", occurrence_id)
    normalized_scope = tuple(sorted(commitment_scope))
    if len(set(normalized_scope)) != len(normalized_scope):
        raise ValueError("commitment_scope fields must be unique")
    if normalized_scope != tuple(sorted(bound_content.keys())):
        raise ValueError("commitment_scope must exactly match bound_content fields")
    if fresh_through == "execution" and execution_binding != "attested":
        raise ValueError("fresh_through=execution requires execution_binding=attested")

    content_digest = content_commitment(bound_content)
    requires_revalidation = fresh_through != "execution"
    envelope_digest = compute_envelope_commitment(
        occurrence_id=occurrence_id,
        content_commitment_value=content_digest,
        commitment_scope=normalized_scope,
        canonicalization_profile=CANONICALIZATION_PROFILE,
        fresh_through=fresh_through,
        execution_binding=execution_binding,
        requires_use_time_revalidation=requires_revalidation,
    )

    return VerificationEnvelope(
        occurrence_id=occurrence_id,
        content_commitment=content_digest,
        envelope_commitment=envelope_digest,
        commitment_scope=normalized_scope,
        canonicalization_profile=CANONICALIZATION_PROFILE,
        fresh_through=fresh_through,
        execution_binding=execution_binding,
        requires_use_time_revalidation=requires_revalidation,
    )


def verify_verification_envelope(
    envelope: VerificationEnvelope,
    bound_content: dict[str, Any],
    *,
    expected_occurrence_id: str,
    required_scope: tuple[str, ...],
    required_fresh_through: str,
    require_execution_attestation: bool,
) -> VerificationEnvelopeValidation:
    """Recompute both binding layers and state exactly where the proof stops."""

    _non_empty("expected_occurrence_id", expected_occurrence_id)
    if required_fresh_through not in FRESHNESS_RANK:
        raise ValueError("required_fresh_through must be issuance, consumption, or execution")

    reproduced_content = content_commitment(bound_content)
    reproduced_envelope = compute_envelope_commitment(
        occurrence_id=envelope.occurrence_id,
        content_commitment_value=envelope.content_commitment,
        commitment_scope=envelope.commitment_scope,
        canonicalization_profile=envelope.canonicalization_profile,
        fresh_through=envelope.fresh_through,
        execution_binding=envelope.execution_binding,
        requires_use_time_revalidation=envelope.requires_use_time_revalidation,
    )
    reasons: list[str] = []

    if envelope.envelope_commitment != reproduced_envelope:
        reasons.append("envelope_commitment_mismatch")
    if envelope.occurrence_id != expected_occurrence_id:
        reasons.append("occurrence_mismatch")
    if envelope.content_commitment != reproduced_content:
        reasons.append("content_commitment_mismatch")
    if envelope.commitment_scope != tuple(sorted(required_scope)):
        reasons.append("commitment_scope_mismatch")
    if tuple(sorted(bound_content.keys())) != envelope.commitment_scope:
        reasons.append("bound_content_scope_mismatch")
    if FRESHNESS_RANK[envelope.fresh_through] < FRESHNESS_RANK[required_fresh_through]:
        reasons.append("freshness_insufficient")
    if require_execution_attestation and envelope.execution_binding != "attested":
        reasons.append("execution_binding_insufficient")

    return VerificationEnvelopeValidation(
        valid=not reasons,
        reasons=tuple(dict.fromkeys(reasons)),
        reproduced_content_commitment=reproduced_content,
        reproduced_envelope_commitment=reproduced_envelope,
        execution_binding=envelope.execution_binding,
        fresh_through=envelope.fresh_through,
        requires_use_time_revalidation=envelope.requires_use_time_revalidation,
    )
