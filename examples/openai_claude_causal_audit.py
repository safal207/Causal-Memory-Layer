"""OpenAI Responses API and Claude Messages API causal-audit adapters.

This SDK-independent example reuses the deterministic CML tool-use scenario from
``grok_xai_causal_audit`` and adds provider-native envelope metadata for:

- OpenAI Responses API ``function_call`` / ``function_call_output`` items.
- Claude Messages API ``tool_use`` / ``tool_result`` content blocks.

No model request, tool execution, file mutation, or network call is performed.

Run from the repository root:

    python examples/openai_claude_causal_audit.py
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Literal

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

ProviderName = Literal["openai", "claude"]


def _tool_records(records: list[CausalRecord]) -> list[CausalRecord]:
    """Return records that represent simulated LLM tool calls."""

    return [
        record
        for record in records
        if isinstance(record.object, dict) and "tool" in record.object
    ]


def _digest(record: CausalRecord, key: str) -> str:
    obj = record.object if isinstance(record.object, dict) else {}
    evidence = obj.get("evidence_bundle", {})
    return str(evidence.get(key, "missing"))


def attach_openai_responses_envelopes(
    records: list[CausalRecord],
) -> list[CausalRecord]:
    """Decorate tool records with OpenAI Responses API correlation metadata.

    The host receives a ``function_call`` item and returns a
    ``function_call_output`` item with the same ``call_id``. CML keeps that
    provider correlation beside the causal parent, permission, risk, approval,
    and evidence metadata already stored on the record.
    """

    decorated = deepcopy(records)
    for index, record in enumerate(_tool_records(decorated), start=1):
        assert isinstance(record.object, dict)
        call_id = f"call_cml_openai_{index}"
        record.object["provider_envelope"] = {
            "provider": "openai",
            "api": "responses",
            "execution_boundary": "host_custom_function",
            "request_item": {
                "type": "function_call",
                "call_id": call_id,
                "name": record.object["tool"],
                "arguments_digest": _digest(record, "request_digest"),
            },
            "result_item": {
                "type": "function_call_output",
                "call_id": call_id,
                "output_digest": _digest(record, "result_digest"),
            },
        }
    return decorated


def attach_claude_messages_envelopes(
    records: list[CausalRecord],
) -> list[CausalRecord]:
    """Decorate tool records with Claude Messages API correlation metadata.

    For client-side tools Claude emits ``stop_reason=tool_use`` and one or more
    ``tool_use`` blocks. The host executes the tool and sends a ``tool_result``
    block whose ``tool_use_id`` points back to the original block.
    """

    decorated = deepcopy(records)
    for index, record in enumerate(_tool_records(decorated), start=1):
        assert isinstance(record.object, dict)
        tool_use_id = f"toolu_cml_claude_{index}"
        result = record.object.get("result", {})
        is_error = isinstance(result, dict) and (
            result.get("status") in {"error", "simulated_not_executed"}
        )
        record.object["provider_envelope"] = {
            "provider": "claude",
            "api": "messages",
            "execution_boundary": "client_side_tool",
            "assistant_stop_reason": "tool_use",
            "request_block": {
                "type": "tool_use",
                "id": tool_use_id,
                "name": record.object["tool"],
                "input_digest": _digest(record, "request_digest"),
            },
            "result_block": {
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "is_error": is_error,
                "content_digest": _digest(record, "result_digest"),
            },
        }
    return decorated


def make_provider_trace(
    provider: ProviderName,
    *,
    valid: bool,
) -> list[CausalRecord]:
    """Build one provider-native valid or invalid synthetic trace."""

    base = make_valid_trace() if valid else make_invalid_trace()
    if provider == "openai":
        return attach_openai_responses_envelopes(base)
    if provider == "claude":
        return attach_claude_messages_envelopes(base)
    raise ValueError(f"Unsupported provider: {provider}")


def provider_summary(records: list[CausalRecord]) -> list[str]:
    """Render provider correlation IDs without exposing private reasoning."""

    lines: list[str] = []
    for record in _tool_records(records):
        assert isinstance(record.object, dict)
        envelope: dict[str, Any] = record.object["provider_envelope"]
        if envelope["provider"] == "openai":
            request = envelope["request_item"]
            result = envelope["result_item"]
            lines.append(
                f"  - {record.id}: {request['type']}({request['call_id']}) "
                f"-> {result['type']}({result['call_id']})"
            )
        else:
            request = envelope["request_block"]
            result = envelope["result_block"]
            lines.append(
                f"  - {record.id}: {request['type']}({request['id']}) "
                f"-> {result['type']}({result['tool_use_id']})"
            )
    return lines


def render_provider_report(
    provider: ProviderName,
    name: str,
    records: list[CausalRecord],
) -> str:
    """Run core CML + Cause Band and append provider-native correlation data."""

    audit_result = audit_trace(records)
    cause_band = VALID_CAUSE_BAND if "Valid" in name else INVALID_CAUSE_BAND
    cause_band_result = evaluate_fixture(cause_band)
    base_report = render_report(name, records, audit_result, cause_band_result)

    heading = (
        "OpenAI Responses correlation:"
        if provider == "openai"
        else "Claude Messages correlation:"
    )
    return "\n".join(
        [
            base_report,
            "",
            heading,
            *provider_summary(records),
            "",
            "Note: provider envelopes are simulated audit metadata. CML remains "
            "a read-only causal-validity layer and does not execute or block tools.",
        ]
    )


def main() -> None:
    cases = [
        ("openai", False, "Invalid OpenAI Responses tool-use trace"),
        ("openai", True, "Valid OpenAI Responses tool-use trace"),
        ("claude", False, "Invalid Claude Messages tool-use trace"),
        ("claude", True, "Valid Claude Messages tool-use trace"),
    ]
    for provider, valid, name in cases:
        records = make_provider_trace(provider, valid=valid)
        print(render_provider_report(provider, name, records))


if __name__ == "__main__":
    main()
