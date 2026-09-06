"""Qwen, Kimi, and DeepSeek causal-audit adapters.

All three examples use an OpenAI-compatible Chat Completions tool-call envelope:
assistant ``tool_calls`` are correlated with ``role=tool`` results through
``tool_call_id``. CML keeps that transport correlation separate from
``parent_cause``, permission, evidence, risk, and human-approval ancestry.

The Kimi thinking-mode example records only safe replay metadata and a digest;
it never stores or exposes raw reasoning content.

No provider request, tool execution, file mutation, or network call is
performed.
"""

from __future__ import annotations

import hashlib
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

ProviderName = Literal["qwen", "kimi", "deepseek"]

PROVIDERS: dict[ProviderName, dict[str, Any]] = {
    "qwen": {
        "api": "dashscope_openai_compatible_chat_completions",
        "deployment": "Alibaba Cloud Model Studio",
        "thinking_mode": "disabled_for_deterministic_pre_tool_gate",
        "strict_mode": "provider_schema_validation",
    },
    "kimi": {
        "api": "openai_compatible_chat_completions",
        "deployment": "Kimi models via Alibaba Cloud Model Studio",
        "thinking_mode": "reasoning_content_replayed_to_provider",
        "strict_mode": "provider_dependent",
    },
    "deepseek": {
        "api": "deepseek_chat_completions",
        "deployment": "DeepSeek API",
        "thinking_mode": "model_dependent",
        "strict_mode": "beta_available",
    },
}


def _tool_records(records: list[CausalRecord]) -> list[CausalRecord]:
    return [
        record
        for record in records
        if isinstance(record.object, dict) and "tool" in record.object
    ]


def _digest(record: CausalRecord, key: str) -> str:
    obj = record.object if isinstance(record.object, dict) else {}
    evidence = obj.get("evidence_bundle", {})
    return str(evidence.get(key, "missing"))


def _reasoning_digest(provider: ProviderName, index: int) -> str:
    simulated = f"{provider}-simulated-reasoning-{index}".encode("utf-8")
    return f"sha256:{hashlib.sha256(simulated).hexdigest()}"


def attach_chat_completions_envelopes(
    records: list[CausalRecord],
    provider: ProviderName,
) -> list[CausalRecord]:
    """Add provider-native Chat Completions transport metadata."""

    decorated = deepcopy(records)
    provider_config = PROVIDERS[provider]

    for index, record in enumerate(_tool_records(decorated), start=1):
        assert isinstance(record.object, dict)
        tool_call_id = f"call_cml_{provider}_{index}"

        envelope: dict[str, Any] = {
            "provider": provider,
            **provider_config,
            "execution_boundary": "host_custom_function",
            "assistant_message": {
                "role": "assistant",
                "finish_reason": "tool_calls",
                "tool_call": {
                    "type": "function",
                    "id": tool_call_id,
                    "function": {
                        "name": record.object["tool"],
                        "arguments_digest": _digest(record, "request_digest"),
                    },
                },
            },
            "tool_message": {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content_digest": _digest(record, "result_digest"),
            },
        }

        if provider == "kimi":
            envelope["reasoning_content_handling"] = {
                "required_in_thinking_mode": True,
                "replayed_to_provider": True,
                "stored_raw_in_cml": False,
                "digest": _reasoning_digest(provider, index),
                "allowed_tool_choice": ["auto", "none"],
            }

        record.object["provider_envelope"] = envelope

    return decorated


def make_provider_trace(
    provider: ProviderName,
    *,
    valid: bool,
) -> list[CausalRecord]:
    base = make_valid_trace() if valid else make_invalid_trace()
    return attach_chat_completions_envelopes(base, provider)


def provider_summary(records: list[CausalRecord]) -> list[str]:
    lines: list[str] = []
    for record in _tool_records(records):
        assert isinstance(record.object, dict)
        envelope = record.object["provider_envelope"]
        call = envelope["assistant_message"]["tool_call"]
        result = envelope["tool_message"]
        lines.append(
            f"  - {record.id}: tool_calls({call['id']}) "
            f"-> role=tool({result['tool_call_id']})"
        )
    return lines


def render_provider_report(
    provider: ProviderName,
    name: str,
    records: list[CausalRecord],
) -> str:
    audit_result = audit_trace(records)
    cause_band = VALID_CAUSE_BAND if "Valid" in name else INVALID_CAUSE_BAND
    band_result = evaluate_fixture(cause_band)
    base_report = render_report(name, records, audit_result, band_result)

    return "\n".join(
        [
            base_report,
            "",
            f"{provider.upper()} Chat Completions correlation:",
            *provider_summary(records),
            "",
            "Note: tool_call_id is transport correlation. CML parent_cause "
            "remains the authorization and responsibility link.",
            "Note: raw reasoning content is not stored in CML.",
            "Note: Cause Band remains experimental and non-normative.",
        ]
    )


def main() -> None:
    for provider in ("qwen", "kimi", "deepseek"):
        invalid = make_provider_trace(provider, valid=False)
        valid = make_provider_trace(provider, valid=True)
        print(
            render_provider_report(
                provider,
                f"Invalid {provider.upper()} tool-use trace",
                invalid,
            )
        )
        print(
            render_provider_report(
                provider,
                f"Valid {provider.upper()} tool-use trace",
                valid,
            )
        )


if __name__ == "__main__":
    main()
