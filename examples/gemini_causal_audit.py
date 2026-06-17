"""Gemini API function-calling causal-audit adapter.

This deterministic, SDK-independent demo maps Gemini custom function calling
into CML records. It models:

- a Gemini ``functionCall`` part with a unique call ``id``;
- a matching ``functionResponse`` part that returns the same ``id``;
- opaque thought-signature preservation metadata for manually managed history;
- CML causal lineage, risk, evidence, and human-approval ancestry.

No Gemini request, tool execution, file mutation, or network call is performed.

Run from the repository root:

    python examples/gemini_causal_audit.py
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from cml.experimental.cause_band import evaluate_fixture
from cml.record import CausalRecord
from examples.grok_xai_causal_audit import (
    INVALID_CAUSE_BAND,
    VALID_CAUSE_BAND,
    audit_trace,
    make_invalid_trace,
    make_valid_trace,
    render_report,
)


def _tool_records(records: list[CausalRecord]) -> list[CausalRecord]:
    """Return records representing simulated LLM tool calls."""

    return [
        record
        for record in records
        if isinstance(record.object, dict) and "tool" in record.object
    ]


def _digest(record: CausalRecord, key: str) -> str:
    obj = record.object if isinstance(record.object, dict) else {}
    evidence = obj.get("evidence_bundle", {})
    return str(evidence.get(key, "missing"))


def attach_gemini_envelopes(
    records: list[CausalRecord],
) -> list[CausalRecord]:
    """Decorate tool records with Gemini generateContent correlation metadata.

    Gemini 3 custom function calls include a unique function-call ``id``. A
    manually constructed ``functionResponse`` should return the exact same
    ``id``. When conversation history is managed manually, thought signatures
    attached to model response parts must be preserved opaquely and returned in
    their original parts. This demo records only preservation state and a
    digest placeholder; it never exposes or interprets hidden reasoning.
    """

    decorated = deepcopy(records)
    for index, record in enumerate(_tool_records(decorated), start=1):
        assert isinstance(record.object, dict)
        function_id = f"gemini_fn_cml_{index}"
        result = record.object.get("result", {})
        is_error = isinstance(result, dict) and (
            result.get("status") in {"error", "simulated_not_executed"}
        )

        record.object["provider_envelope"] = {
            "provider": "gemini",
            "api": "generateContent",
            "execution_boundary": "host_custom_function",
            "automatic_function_calling": "disabled_for_pre_tool_gate",
            "model_part": {
                "sdk_type": "function_call",
                "wire_key": "functionCall",
                "id": function_id,
                "name": record.object["tool"],
                "args_digest": _digest(record, "request_digest"),
                "thought_signature": {
                    "present": True,
                    "preserved_opaque": True,
                    "stored_raw": False,
                    "digest": f"sha256:simulated-thought-signature-{index}",
                },
            },
            "user_part": {
                "sdk_type": "function_response",
                "wire_key": "functionResponse",
                "id": function_id,
                "name": record.object["tool"],
                "response_digest": _digest(record, "result_digest"),
                "is_error": is_error,
            },
        }
    return decorated


def make_gemini_trace(*, valid: bool) -> list[CausalRecord]:
    """Build one Gemini-native valid or invalid synthetic trace."""

    base = make_valid_trace() if valid else make_invalid_trace()
    return attach_gemini_envelopes(base)


def provider_summary(records: list[CausalRecord]) -> list[str]:
    """Render Gemini call/response correlation without private reasoning."""

    lines: list[str] = []
    for record in _tool_records(records):
        assert isinstance(record.object, dict)
        envelope: dict[str, Any] = record.object["provider_envelope"]
        call = envelope["model_part"]
        response = envelope["user_part"]
        lines.append(
            f"  - {record.id}: {call['wire_key']}({call['id']}) "
            f"-> {response['wire_key']}({response['id']})"
        )
    return lines


def render_gemini_report(
    name: str,
    records: list[CausalRecord],
) -> str:
    """Run core CML + Cause Band and append Gemini correlation metadata."""

    audit_result = audit_trace(records)
    cause_band = VALID_CAUSE_BAND if "Valid" in name else INVALID_CAUSE_BAND
    cause_band_result = evaluate_fixture(cause_band)
    base_report = render_report(name, records, audit_result, cause_band_result)

    return "\n".join(
        [
            base_report,
            "",
            "Gemini generateContent correlation:",
            *provider_summary(records),
            "",
            "Note: function IDs and opaque thought-signature preservation are "
            "transport metadata. CML parent_cause remains the causal "
            "authorization and responsibility link.",
            "Note: Cause Band remains experimental and non-normative.",
        ]
    )


def main() -> None:
    invalid = make_gemini_trace(valid=False)
    valid = make_gemini_trace(valid=True)

    print(render_gemini_report("Invalid Gemini function-calling trace", invalid))
    print(render_gemini_report("Valid Gemini function-calling trace", valid))


if __name__ == "__main__":
    main()
