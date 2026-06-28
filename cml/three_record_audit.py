"""Provider-neutral causal audit for trustworthy three-record transitions.

This module validates causal joins across authorization, observation, and
response-integrity records. It does not issue authority, execute actions, or
re-evaluate the semantic truth of tool output.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable


PROFILE = "org.cml.three-record-causal-audit.v0.1"
CLAIM_BOUNDARY = (
    "CML validates record references, transition/subject consistency, action "
    "bindings, executable-authority ancestry, claim-to-observation lineage, "
    "and causal graph shape. It preserves but does not author authority, "
    "execution, or response-integrity verdicts."
)


class ThreeRecordAuditError(ValueError):
    """Raised when the top-level audit input is structurally invalid."""


class FindingCode:
    MISSING_AUTHORIZATION_PARENT = "CML-TTR-R1-MISSING_AUTHORIZATION_PARENT"
    OBSERVATION_ACTION_BINDING_MISMATCH = (
        "CML-TTR-R2-OBSERVATION_ACTION_BINDING_MISMATCH"
    )
    OBSERVATION_WITHOUT_EXECUTABLE_AUTHORITY = (
        "CML-TTR-R3-OBSERVATION_WITHOUT_EXECUTABLE_AUTHORITY"
    )
    CLAIM_UNRELATED_OBSERVATION = "CML-TTR-R4-CLAIM_UNRELATED_OBSERVATION"
    STALE_OR_CONSUMED_AUTHORITY_AS_LIVE = (
        "CML-TTR-R5-STALE_OR_CONSUMED_AUTHORITY_AS_LIVE"
    )
    CROSS_SUBJECT_OR_TRANSITION_JOIN = (
        "CML-TTR-R6-CROSS_SUBJECT_OR_TRANSITION_JOIN"
    )
    SUPPORTED_CLAIM_NO_LINEAGE = "CML-TTR-R7-SUPPORTED_CLAIM_NO_LINEAGE"
    CAUSAL_CYCLE_OR_AMBIGUOUS_ROOT = (
        "CML-TTR-R8-CAUSAL_CYCLE_OR_AMBIGUOUS_ROOT"
    )
    RECORD_REFERENCE_MISMATCH = "CML-TTR-R9-RECORD_REFERENCE_MISMATCH"


@dataclass(frozen=True)
class CausalFinding:
    code: str
    severity: str
    edge: str
    record_ids: tuple[str, ...]
    message: str
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "severity": self.severity,
            "edge": self.edge,
            "record_ids": list(self.record_ids),
            "message": self.message,
        }
        if self.context:
            result["context"] = self.context
        return result


def canonical_json(value: Any) -> str:
    """Return deterministic JSON for the fixture's JSON-only value domain."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def record_ref(record: dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def wrap_record(record: dict[str, Any]) -> dict[str, Any]:
    return {"record": record, "record_ref": record_ref(record)}


def _require_wrapper(value: Any, label: str) -> tuple[dict[str, Any], str]:
    if not isinstance(value, dict):
        raise ThreeRecordAuditError(f"{label} must be an object")
    record = value.get("record")
    reference = value.get("record_ref")
    if not isinstance(record, dict) or not isinstance(reference, str):
        raise ThreeRecordAuditError(
            f"{label} must contain object record and string record_ref"
        )
    return record, reference


def _text(record: dict[str, Any], field_name: str) -> str | None:
    value = record.get(field_name)
    return value if isinstance(value, str) and value else None


def _authority_dimension(record: dict[str, Any] | None) -> str:
    if record is None:
        return "NOT_EVALUATED"
    decision = str(record.get("decision", "")).upper()
    state = str(record.get("current_state", "")).upper()
    consumption = str(record.get("consumption_state", "")).upper()

    if state == "EXPIRED_AT_REPORT":
        return "EXPIRED_AT_REPORT"
    if state == "EXPIRED":
        return "EXPIRED"
    if state == "CONSUMED" or consumption == "CONSUMED":
        return "CONSUMED"
    if state == "REVALIDATION_REQUIRED":
        return "REVALIDATION_REQUIRED"
    if decision in {"DENY", "BLOCK", "REJECT"} or state in {"DENIED", "BLOCKED"}:
        return "DENIED"
    if decision in {"DEFER", "HOLD", "ESCALATE"} or state in {
        "PENDING",
        "PENDING_APPROVAL",
    }:
        return "PENDING"
    if decision in {"ALLOW", "ACCEPT"} and state in {"", "ACTIVE"}:
        return "VALID"
    return "UNKNOWN"


def _execution_dimension(observations: Iterable[dict[str, Any]]) -> str:
    statuses = [str(record.get("execution_status", "")).upper() for record in observations]
    if any(status == "EXECUTED" for status in statuses):
        return "OBSERVED_EXECUTED"
    if any(status in {"BLOCKED", "REFUSED"} for status in statuses):
        return "OBSERVED_BLOCKED"
    if any(status == "ERRORED" for status in statuses):
        return "OBSERVED_ERRORED"
    if statuses:
        return "OBSERVED_OTHER"
    return "NOT_OBSERVED"


def _integrity_dimension(record: dict[str, Any] | None) -> str:
    if record is None:
        return "NOT_EVALUATED"
    verdict = str(record.get("overall_verdict", "NOT_EVALUATED")).upper()
    if verdict in {"VERIFIED", "FAILED", "PARTIAL", "NOT_EVALUATED"}:
        return verdict
    return "UNKNOWN"


def _is_executable_authority(record: dict[str, Any]) -> bool:
    return _authority_dimension(record) == "VALID"


def _is_stale_or_consumed(record: dict[str, Any]) -> bool:
    return _authority_dimension(record) in {
        "EXPIRED",
        "EXPIRED_AT_REPORT",
        "CONSUMED",
        "REVALIDATION_REQUIRED",
    }


def _finding(
    findings: list[CausalFinding],
    *,
    code: str,
    edge: str,
    record_ids: Iterable[str],
    message: str,
    context: dict[str, Any] | None = None,
) -> None:
    findings.append(
        CausalFinding(
            code=code,
            severity="FAIL",
            edge=edge,
            record_ids=tuple(record_ids),
            message=message,
            context=context or {},
        )
    )


def _detect_cycle(graph: dict[str, set[str]]) -> list[str] | None:
    visiting: set[str] = set()
    visited: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        if node in visiting:
            start = stack.index(node)
            return stack[start:] + [node]
        if node in visited:
            return None
        visiting.add(node)
        stack.append(node)
        for parent in sorted(graph.get(node, set())):
            if parent not in graph:
                continue
            cycle = visit(parent)
            if cycle:
                return cycle
        stack.pop()
        visiting.remove(node)
        visited.add(node)
        return None

    for node in sorted(graph):
        cycle = visit(node)
        if cycle:
            return cycle
    return None


def audit_three_record_transition(
    *,
    authorization_record: dict[str, Any] | None,
    observation_records: list[dict[str, Any]],
    response_integrity_record: dict[str, Any] | None,
) -> dict[str, Any]:
    """Audit causal joins while preserving independent lifecycle verdicts."""

    if not isinstance(observation_records, list):
        raise ThreeRecordAuditError("observation_records must be an array")

    findings: list[CausalFinding] = []
    graph: dict[str, set[str]] = {}
    known_records: dict[str, dict[str, Any]] = {}

    authorization: dict[str, Any] | None = None
    authorization_ref: str | None = None
    if authorization_record is not None:
        authorization, authorization_ref = _require_wrapper(
            authorization_record, "authorization_record"
        )
        known_records[authorization_ref] = authorization
        graph[authorization_ref] = set()
        if record_ref(authorization) != authorization_ref:
            _finding(
                findings,
                code=FindingCode.RECORD_REFERENCE_MISMATCH,
                edge="record -> record_ref",
                record_ids=[authorization_ref],
                message="Authorization record reference does not match canonical bytes.",
            )
        parent_refs = authorization.get("causal_parent_refs", [])
        if parent_refs is None:
            parent_refs = []
        if not isinstance(parent_refs, list) or any(
            not isinstance(item, str) for item in parent_refs
        ):
            raise ThreeRecordAuditError(
                "authorization_record.record.causal_parent_refs must be a string array"
            )
        graph[authorization_ref].update(parent_refs)
        if not parent_refs and authorization.get("causal_root") is not True:
            _finding(
                findings,
                code=FindingCode.CAUSAL_CYCLE_OR_AMBIGUOUS_ROOT,
                edge="authorization -> causal root",
                record_ids=[authorization_ref],
                message=(
                    "Authorization has neither causal parents nor an explicit "
                    "causal_root=true marker."
                ),
            )

    observations: list[tuple[dict[str, Any], str]] = []
    for index, wrapper in enumerate(observation_records):
        observation, observation_ref = _require_wrapper(
            wrapper, f"observation_records[{index}]"
        )
        observations.append((observation, observation_ref))
        known_records[observation_ref] = observation
        graph[observation_ref] = set()
        if record_ref(observation) != observation_ref:
            _finding(
                findings,
                code=FindingCode.RECORD_REFERENCE_MISMATCH,
                edge="record -> record_ref",
                record_ids=[observation_ref],
                message="Observation record reference does not match canonical bytes.",
            )

        parent = _text(observation, "authorization_ref")
        if parent:
            graph[observation_ref].add(parent)
        if not parent or authorization_ref is None or parent != authorization_ref:
            _finding(
                findings,
                code=FindingCode.MISSING_AUTHORIZATION_PARENT,
                edge="observation -> authorization",
                record_ids=[observation_ref, parent or "missing"],
                message="Observation does not reference the supplied authorization record.",
                context={"authorization_ref": parent},
            )
        if authorization is not None:
            if (
                observation.get("transition_id") != authorization.get("transition_id")
                or observation.get("subject_id") != authorization.get("subject_id")
            ):
                _finding(
                    findings,
                    code=FindingCode.CROSS_SUBJECT_OR_TRANSITION_JOIN,
                    edge="authorization -> observation",
                    record_ids=[authorization_ref or "missing", observation_ref],
                    message=(
                        "Authorization and observation do not share the same "
                        "transition_id and subject_id."
                    ),
                )
            if (
                observation.get("action_identity_digest")
                != authorization.get("action_identity_digest")
                or observation.get("binding_digest")
                != authorization.get("binding_digest")
            ):
                _finding(
                    findings,
                    code=FindingCode.OBSERVATION_ACTION_BINDING_MISMATCH,
                    edge="authorization -> observation binding",
                    record_ids=[authorization_ref or "missing", observation_ref],
                    message=(
                        "Observation action_identity_digest or binding_digest "
                        "does not match authorization."
                    ),
                )
            if str(observation.get("execution_status", "")).upper() == "EXECUTED":
                if not _is_executable_authority(authorization):
                    _finding(
                        findings,
                        code=FindingCode.OBSERVATION_WITHOUT_EXECUTABLE_AUTHORITY,
                        edge="authorization -> executed observation",
                        record_ids=[authorization_ref or "missing", observation_ref],
                        message=(
                            "Executed observation descends from authority that "
                            "was not executable."
                        ),
                        context={
                            "authority_dimension": _authority_dimension(authorization)
                        },
                    )
                if _is_stale_or_consumed(authorization):
                    _finding(
                        findings,
                        code=FindingCode.STALE_OR_CONSUMED_AUTHORITY_AS_LIVE,
                        edge="stale authority -> executed observation",
                        record_ids=[authorization_ref or "missing", observation_ref],
                        message=(
                            "Expired, consumed, or revalidation-required authority "
                            "was used as live execution ancestry."
                        ),
                    )

    integrity: dict[str, Any] | None = None
    integrity_ref: str | None = None
    if response_integrity_record is not None:
        integrity, integrity_ref = _require_wrapper(
            response_integrity_record, "response_integrity_record"
        )
        known_records[integrity_ref] = integrity
        graph[integrity_ref] = set()
        if record_ref(integrity) != integrity_ref:
            _finding(
                findings,
                code=FindingCode.RECORD_REFERENCE_MISMATCH,
                edge="record -> record_ref",
                record_ids=[integrity_ref],
                message="Response integrity record reference does not match canonical bytes.",
            )

        parent_authorization = _text(integrity, "authorization_ref")
        if parent_authorization:
            graph[integrity_ref].add(parent_authorization)
        for reference in integrity.get("observation_refs", []):
            if isinstance(reference, str):
                graph[integrity_ref].add(reference)

        if authorization is not None:
            if (
                integrity.get("transition_id") != authorization.get("transition_id")
                or integrity.get("subject_id") != authorization.get("subject_id")
            ):
                _finding(
                    findings,
                    code=FindingCode.CROSS_SUBJECT_OR_TRANSITION_JOIN,
                    edge="authorization -> response integrity",
                    record_ids=[authorization_ref or "missing", integrity_ref],
                    message=(
                        "Authorization and response integrity do not share the "
                        "same transition_id and subject_id."
                    ),
                )
            if parent_authorization != authorization_ref:
                _finding(
                    findings,
                    code=FindingCode.MISSING_AUTHORIZATION_PARENT,
                    edge="response integrity -> authorization",
                    record_ids=[integrity_ref, parent_authorization or "missing"],
                    message=(
                        "Response integrity does not reference the supplied "
                        "authorization record."
                    ),
                )

        known_observation_refs = {reference for _, reference in observations}
        declared_observation_refs = integrity.get("observation_refs", [])
        if not isinstance(declared_observation_refs, list) or any(
            not isinstance(item, str) for item in declared_observation_refs
        ):
            raise ThreeRecordAuditError(
                "response_integrity_record.record.observation_refs must be a string array"
            )
        for reference in declared_observation_refs:
            if reference not in known_observation_refs:
                _finding(
                    findings,
                    code=FindingCode.CLAIM_UNRELATED_OBSERVATION,
                    edge="response integrity -> observation",
                    record_ids=[integrity_ref, reference],
                    message=(
                        "Response integrity references an observation outside "
                        "the supplied transition record set."
                    ),
                )

        claims = integrity.get("claims", [])
        if not isinstance(claims, list):
            raise ThreeRecordAuditError(
                "response_integrity_record.record.claims must be an array"
            )
        for index, claim in enumerate(claims):
            if not isinstance(claim, dict):
                raise ThreeRecordAuditError(
                    f"response integrity claim {index} must be an object"
                )
            claim_id = str(claim.get("claim_id", f"claim-{index}"))
            claim_refs = claim.get("observation_refs", [])
            if not isinstance(claim_refs, list) or any(
                not isinstance(item, str) for item in claim_refs
            ):
                raise ThreeRecordAuditError(
                    f"response integrity claim {claim_id} observation_refs must be an array"
                )
            for reference in claim_refs:
                if reference not in known_observation_refs:
                    _finding(
                        findings,
                        code=FindingCode.CLAIM_UNRELATED_OBSERVATION,
                        edge="claim -> observation",
                        record_ids=[integrity_ref, claim_id, reference],
                        message=(
                            f"Claim {claim_id} references an observation outside "
                            "the supplied transition."
                        ),
                    )
            if str(claim.get("verdict", "")).upper() == "SUPPORTED":
                if not claim_refs or any(
                    reference not in known_observation_refs for reference in claim_refs
                ):
                    _finding(
                        findings,
                        code=FindingCode.SUPPORTED_CLAIM_NO_LINEAGE,
                        edge="supported claim -> observation",
                        record_ids=[integrity_ref, claim_id],
                        message=(
                            f"Supported claim {claim_id} lacks complete observation lineage."
                        ),
                    )

    cycle = _detect_cycle(graph)
    if cycle:
        _finding(
            findings,
            code=FindingCode.CAUSAL_CYCLE_OR_AMBIGUOUS_ROOT,
            edge="causal graph",
            record_ids=cycle,
            message="A causal cycle was detected across transition records.",
            context={"cycle": cycle},
        )

    unique_findings: list[CausalFinding] = []
    seen_findings: set[tuple[str, str, tuple[str, ...]]] = set()
    for item in findings:
        key = (item.code, item.edge, item.record_ids)
        if key not in seen_findings:
            seen_findings.add(key)
            unique_findings.append(item)

    dimensions = {
        "authority": _authority_dimension(authorization),
        "execution": _execution_dimension(record for record, _ in observations),
        "response_integrity": _integrity_dimension(integrity),
        "causal_validity": "INVALID" if unique_findings else "VALID",
    }

    return {
        "schema_version": 1,
        "profile": PROFILE,
        "status": "FAILED" if unique_findings else "VERIFIED",
        "dimensions": dimensions,
        "records": {
            "authorization_ref": authorization_ref,
            "observation_refs": [reference for _, reference in observations],
            "response_integrity_ref": integrity_ref,
        },
        "summary": {
            "record_count": len(known_records),
            "finding_count": len(unique_findings),
            "passed": not unique_findings,
        },
        "findings": [finding.to_dict() for finding in unique_findings],
        "claim_boundary": CLAIM_BOUNDARY,
    }
