"""Content-addressed pre-tool authorization decisions.

``GuardrailDecisionV1`` binds every authoritative decision input into one
canonical SHA-256 preimage. Signatures, external anchors, and provider
independence remain separate guarantees and may be attached as a proof sidecar
without changing the deterministic decision identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any, Literal, Mapping

from cml.integrations.action_ref import validate_rfc3339_milliseconds_utc

GUARDRAIL_DECISION_SCHEMA = "cml-guardrail-decision-v1"
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
VERDICTS = frozenset({"ALLOW", "DENY", "SUSPEND"})
CLAIM_FIELDS = frozenset(
    {
        "request_digest",
        "verdict",
        "reason_code",
        "provider_id",
        "policy_digest",
        "authorization_source_digest",
        "issued_at",
        "expires_at",
    }
)
TOP_LEVEL_FIELDS = frozenset({"schema_version", "decision_id", "claims", "proof"})

GuardrailVerdict = Literal["ALLOW", "DENY", "SUSPEND"]


def _validate_non_empty_token(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{label} must not contain leading or trailing whitespace")
    return value


def _validate_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not SHA256_HEX.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase 64-character SHA-256 digest")
    return value


def _parse_timestamp(value: str) -> datetime:
    validate_rfc3339_milliseconds_utc(value)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )


def _freeze_json(value: Any, *, path: str = "proof") -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} keys must be strings")
            frozen[key] = _freeze_json(item, path=f"{path}.{key}")
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(
            _freeze_json(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        )
    raise ValueError(f"{path} contains a non-JSON value: {type(value).__name__}")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _require_exact_fields(
    payload: Mapping[str, Any], *, expected: frozenset[str], label: str
) -> None:
    observed = frozenset(payload)
    missing = sorted(expected - observed)
    unknown = sorted(observed - expected)
    if missing:
        raise ValueError(f"{label} is missing fields: {', '.join(missing)}")
    if unknown:
        raise ValueError(f"{label} contains unknown fields: {', '.join(unknown)}")


@dataclass(frozen=True)
class GuardrailDecisionClaimsV1:
    """Authoritative fields bound into ``decision_id``."""

    request_digest: str
    verdict: GuardrailVerdict
    reason_code: str
    provider_id: str
    policy_digest: str
    authorization_source_digest: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _validate_digest(self.request_digest, label="request_digest")
        _validate_digest(self.policy_digest, label="policy_digest")
        _validate_digest(
            self.authorization_source_digest,
            label="authorization_source_digest",
        )
        if self.verdict not in VERDICTS:
            raise ValueError("verdict must be ALLOW, DENY, or SUSPEND")
        _validate_non_empty_token(self.reason_code, label="reason_code")
        _validate_non_empty_token(self.provider_id, label="provider_id")
        issued = _parse_timestamp(self.issued_at)
        expires = _parse_timestamp(self.expires_at)
        if expires <= issued:
            raise ValueError("expires_at must be strictly later than issued_at")

    def to_mapping(self) -> dict[str, str]:
        return {
            "request_digest": self.request_digest,
            "verdict": self.verdict,
            "reason_code": self.reason_code,
            "provider_id": self.provider_id,
            "policy_digest": self.policy_digest,
            "authorization_source_digest": self.authorization_source_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class GuardrailDecisionV1:
    """A content-addressed decision plus an optional non-authoritative proof."""

    decision_id: str
    claims: GuardrailDecisionClaimsV1
    proof: Mapping[str, Any] | None = field(default=None, compare=False)
    schema_version: str = GUARDRAIL_DECISION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != GUARDRAIL_DECISION_SCHEMA:
            raise ValueError(
                f"schema_version must be {GUARDRAIL_DECISION_SCHEMA!r}"
            )
        _validate_digest(self.decision_id, label="decision_id")
        if not isinstance(self.claims, GuardrailDecisionClaimsV1):
            raise TypeError("claims must be GuardrailDecisionClaimsV1")
        if self.proof is not None:
            if not isinstance(self.proof, Mapping):
                raise TypeError("proof must be a JSON object or null")
            object.__setattr__(self, "proof", _freeze_json(self.proof))

    def preimage(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "claims": self.claims.to_mapping(),
        }

    def to_mapping(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "decision_id": self.decision_id,
            "claims": self.claims.to_mapping(),
        }
        if self.proof is not None:
            payload["proof"] = _thaw_json(self.proof)
        return payload


@dataclass(frozen=True)
class GuardrailDecisionFinding:
    code: str
    message: str


@dataclass(frozen=True)
class GuardrailDecisionVerificationResult:
    findings: tuple[GuardrailDecisionFinding, ...]
    expected_decision_id: str

    def passed(self) -> bool:
        return not self.findings


def canonical_guardrail_decision_json(
    claims: GuardrailDecisionClaimsV1,
) -> str:
    """Return the canonical schema+claims preimage used for identity."""

    if not isinstance(claims, GuardrailDecisionClaimsV1):
        raise TypeError("claims must be GuardrailDecisionClaimsV1")
    return json.dumps(
        {
            "schema_version": GUARDRAIL_DECISION_SCHEMA,
            "claims": claims.to_mapping(),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def derive_guardrail_decision_id(claims: GuardrailDecisionClaimsV1) -> str:
    canonical = canonical_guardrail_decision_json(claims)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def issue_guardrail_decision(
    *,
    request_digest: str,
    verdict: GuardrailVerdict,
    reason_code: str,
    provider_id: str,
    policy_digest: str,
    authorization_source_digest: str,
    issued_at: str,
    expires_at: str,
    proof: Mapping[str, Any] | None = None,
) -> GuardrailDecisionV1:
    claims = GuardrailDecisionClaimsV1(
        request_digest=request_digest,
        verdict=verdict,
        reason_code=reason_code,
        provider_id=provider_id,
        policy_digest=policy_digest,
        authorization_source_digest=authorization_source_digest,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return GuardrailDecisionV1(
        decision_id=derive_guardrail_decision_id(claims),
        claims=claims,
        proof=proof,
    )


def guardrail_decision_from_mapping(
    payload: Mapping[str, Any],
) -> GuardrailDecisionV1:
    if not isinstance(payload, Mapping):
        raise TypeError("guardrail decision must be a JSON object")

    allowed_top_level = (
        TOP_LEVEL_FIELDS if "proof" in payload else TOP_LEVEL_FIELDS - {"proof"}
    )
    _require_exact_fields(payload, expected=allowed_top_level, label="decision")

    claims_payload = payload["claims"]
    if not isinstance(claims_payload, Mapping):
        raise ValueError("claims must be a JSON object")
    _require_exact_fields(claims_payload, expected=CLAIM_FIELDS, label="claims")

    claims = GuardrailDecisionClaimsV1(
        request_digest=claims_payload["request_digest"],
        verdict=claims_payload["verdict"],
        reason_code=claims_payload["reason_code"],
        provider_id=claims_payload["provider_id"],
        policy_digest=claims_payload["policy_digest"],
        authorization_source_digest=claims_payload[
            "authorization_source_digest"
        ],
        issued_at=claims_payload["issued_at"],
        expires_at=claims_payload["expires_at"],
    )
    proof = payload.get("proof")
    return GuardrailDecisionV1(
        schema_version=payload["schema_version"],
        decision_id=payload["decision_id"],
        claims=claims,
        proof=proof,
    )


def load_guardrail_decision_json(text: str) -> GuardrailDecisionV1:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    try:
        payload = json.loads(text, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError("guardrail decision is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("guardrail decision must contain a JSON object")
    return guardrail_decision_from_mapping(payload)


def verify_guardrail_decision(
    decision: GuardrailDecisionV1,
    *,
    now: datetime | None = None,
) -> GuardrailDecisionVerificationResult:
    if not isinstance(decision, GuardrailDecisionV1):
        raise TypeError("decision must be GuardrailDecisionV1")

    expected_id = derive_guardrail_decision_id(decision.claims)
    findings: list[GuardrailDecisionFinding] = []
    if decision.decision_id != expected_id:
        findings.append(
            GuardrailDecisionFinding(
                code="CML-GUARDRAIL-DECISION-ID-MISMATCH",
                message=(
                    "decision_id does not match the canonical schema+claims preimage"
                ),
            )
        )

    observed_now = now or datetime.now(timezone.utc)
    if not isinstance(observed_now, datetime):
        raise TypeError("now must be a datetime or null")
    if observed_now.tzinfo is None or observed_now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    observed_now = observed_now.astimezone(timezone.utc)

    issued = _parse_timestamp(decision.claims.issued_at)
    expires = _parse_timestamp(decision.claims.expires_at)
    if observed_now < issued:
        findings.append(
            GuardrailDecisionFinding(
                code="CML-GUARDRAIL-DECISION-NOT-YET-VALID",
                message="decision issued_at is later than the verification time",
            )
        )
    if observed_now >= expires:
        findings.append(
            GuardrailDecisionFinding(
                code="CML-GUARDRAIL-DECISION-EXPIRED",
                message="decision expires_at is not later than the verification time",
            )
        )

    findings.sort(key=lambda item: (item.code, item.message))
    return GuardrailDecisionVerificationResult(
        findings=tuple(findings),
        expected_decision_id=expected_id,
    )
