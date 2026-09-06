#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import importlib.util
import json
import sys
import tempfile
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parent
CAEP_DIR = HERE.parent
INTEROP_DIR = CAEP_DIR / "interoperability_demo"
sys.path.insert(0, str(INTEROP_DIR))

from common import read_json, write_json  # noqa: E402
from record_builder import build_record, seal  # noqa: E402


def snapshot(source: Path, destination: Path) -> None:
    write_json(destination, read_json(source))


def load_caep_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "validate_caep",
        CAEP_DIR / "validate_caep.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load the canonical CAEP validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_caep_bundle(bundle: dict[str, Any]) -> None:
    validator = load_caep_validator()
    schema = validator.load_json(CAEP_DIR / "caep.schema.json")
    happy = bundle["happy_path"]["record"]
    diverged = bundle["recovery_path"]["diverged_record"]
    recovered = bundle["recovery_path"]["recovered_record"]
    failures = {
        "happy": validator.validate_record(schema, happy),
        "diverged": validator.validate_record(schema, diverged),
        "recovered": validator.validate_record(schema, recovered, [diverged]),
    }
    invalid = {name: errors for name, errors in failures.items() if errors}
    if invalid:
        raise RuntimeError(
            "generated CAEP bundle is invalid: "
            + json.dumps(invalid, sort_keys=True)
        )


def protocol_version(initialization: Any) -> str:
    return str(
        getattr(
            initialization,
            "protocolVersion",
            getattr(initialization, "protocol_version", "unknown"),
        )
    )


def structured_result(result: Any) -> dict[str, Any]:
    structured = getattr(
        result,
        "structuredContent",
        getattr(result, "structured_content", None),
    )
    if isinstance(structured, dict):
        return structured
    for content in result.content:
        if isinstance(content, types.TextContent):
            parsed = json.loads(content.text)
            if isinstance(parsed, dict):
                return parsed
    raise RuntimeError("MCP tool did not return a JSON object")


async def open_session(
    stack: AsyncExitStack,
    script: str,
    ledger: Path,
) -> tuple[ClientSession, str, list[str]]:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / script), "--ledger", str(ledger)],
    )
    read_stream, write_stream = await stack.enter_async_context(
        stdio_client(parameters)
    )
    session = await stack.enter_async_context(
        ClientSession(read_stream, write_stream)
    )
    initialization = await session.initialize()
    tools = await session.list_tools()
    return session, protocol_version(initialization), [tool.name for tool in tools.tools]


async def call_json(
    session: ClientSession,
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    return structured_result(await session.call_tool(tool_name, arguments=arguments))


def mcp_record(
    *,
    protocol: str,
    transport_evidence: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    record = build_record(**kwargs)
    record["action"]["dispatch"]["protocol_version"] = protocol
    record["authorization"]["expires_at"] = "2026-07-30T02:00:00Z"
    record["extensions"].pop(
        "org.causal-memory-layer.interoperability-demo",
        None,
    )
    record["extensions"]["org.causal-memory-layer.mcp-sdk-adapter"] = {
        "transport": "stdio",
        "sdk_package": "mcp",
        "sdk_version": importlib.metadata.version("mcp"),
        "real_mcp_session": True,
        **transport_evidence,
    }
    return seal(record)


async def run_happy(
    workdir: Path,
    ledger: Path,
    action: ClientSession,
    verifier: ClientSession,
    protocol: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    before = workdir / "happy-before.json"
    observation_path = workdir / "happy-observation.json"
    outcome_path = workdir / "happy-outcome.json"
    after = workdir / "happy-after.json"
    verification_path = workdir / "happy-verification.json"
    write_json(ledger, {"payments": []})

    observation = await call_json(action, "observe_order", {"order_id": "order-88"})
    write_json(observation_path, observation)
    snapshot(ledger, before)
    outcome = await call_json(
        action,
        "create_payment",
        {
            "order_id": "order-88",
            "payment_id": "payment_A",
            "observation_digest": observation["observation_digest"],
        },
    )
    write_json(outcome_path, outcome)
    snapshot(ledger, after)
    verification = await call_json(
        verifier,
        "verify_single_payment",
        {"order_id": "order-88"},
    )
    write_json(verification_path, verification)

    record = mcp_record(
        protocol=protocol,
        transport_evidence=evidence,
        episode_id="mcp_sdk_happy_verified",
        workflow_id="mcp_sdk_happy_workflow",
        status="verified",
        order_id="order-88",
        action_tool="create_payment",
        request_path=observation_path,
        response_path=outcome_path,
        verification_path=verification_path,
        state_before_path=before,
        state_after_path=after,
        started_at="2026-07-30T00:00:01Z",
        completed_at="2026-07-30T00:00:02Z",
        observed_at="2026-07-30T00:00:03Z",
        verified_at="2026-07-30T00:00:04Z",
        verification_verdict=verification["verdict"],
        verification_result=verification["result"],
        recovery_status="available",
    )
    return {"record": record, "verification": verification}


async def run_recovery(
    workdir: Path,
    ledger: Path,
    action: ClientSession,
    verifier: ClientSession,
    protocol: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    observation_path = workdir / "recovery-observation.json"
    before_create = workdir / "recovery-before-create.json"
    create_outcome_path = workdir / "recovery-create-outcome.json"
    after_create = workdir / "recovery-after-create.json"
    diverged_verification_path = workdir / "recovery-diverged-verification.json"
    before_cancel = workdir / "recovery-before-cancel.json"
    cancel_outcome_path = workdir / "recovery-cancel-outcome.json"
    after_cancel = workdir / "recovery-after-cancel.json"
    recovered_verification_path = workdir / "recovery-final-verification.json"
    write_json(ledger, {"payments": []})

    observation = await call_json(action, "observe_order", {"order_id": "order-88"})
    write_json(observation_path, observation)

    parallel = read_json(ledger)
    parallel["payments"].append(
        {
            "payment_id": "payment_A",
            "order_id": "order-88",
            "status": "succeeded",
        }
    )
    write_json(ledger, parallel)
    snapshot(ledger, before_create)

    outcome = await call_json(
        action,
        "create_payment",
        {
            "order_id": "order-88",
            "payment_id": "payment_B",
            "observation_digest": observation["observation_digest"],
        },
    )
    write_json(create_outcome_path, outcome)
    snapshot(ledger, after_create)
    diverged_verification = await call_json(
        verifier,
        "verify_single_payment",
        {"order_id": "order-88"},
    )
    write_json(diverged_verification_path, diverged_verification)

    diverged = mcp_record(
        protocol=protocol,
        transport_evidence=evidence,
        episode_id="mcp_sdk_duplicate_diverged",
        workflow_id="mcp_sdk_recovery_workflow",
        status="contained",
        order_id="order-88",
        action_tool="create_payment",
        request_path=observation_path,
        response_path=create_outcome_path,
        verification_path=diverged_verification_path,
        state_before_path=before_create,
        state_after_path=after_create,
        started_at="2026-07-30T00:10:02Z",
        completed_at="2026-07-30T00:10:03Z",
        observed_at="2026-07-30T00:10:03Z",
        verified_at="2026-07-30T00:10:04Z",
        verification_verdict=diverged_verification["verdict"],
        verification_result=diverged_verification["result"],
        recovery_status="contained",
    )

    snapshot(ledger, before_cancel)
    cancel_outcome = await call_json(
        action,
        "cancel_payment",
        {"payment_id": "payment_B"},
    )
    write_json(cancel_outcome_path, cancel_outcome)
    snapshot(ledger, after_cancel)
    recovered_verification = await call_json(
        verifier,
        "verify_single_payment",
        {"order_id": "order-88"},
    )
    write_json(recovered_verification_path, recovered_verification)

    recovered = mcp_record(
        protocol=protocol,
        transport_evidence=evidence,
        episode_id="mcp_sdk_duplicate_recovered",
        workflow_id="mcp_sdk_recovery_workflow",
        status="recovered",
        order_id="order-88",
        action_tool="cancel_payment",
        request_path=before_cancel,
        response_path=cancel_outcome_path,
        verification_path=recovered_verification_path,
        state_before_path=before_cancel,
        state_after_path=after_cancel,
        started_at="2026-07-30T00:10:05Z",
        completed_at="2026-07-30T00:10:06Z",
        observed_at="2026-07-30T00:10:06Z",
        verified_at="2026-07-30T00:10:07Z",
        verification_verdict=recovered_verification["verdict"],
        verification_result=recovered_verification["result"],
        recovery_status="recovered",
        parent=diverged,
    )
    return {
        "diverged_record": diverged,
        "recovered_record": recovered,
        "diverged_verification": diverged_verification,
        "recovered_verification": recovered_verification,
    }


async def run(output: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="caep-mcp-sdk-") as temp_dir:
        workdir = Path(temp_dir)
        session_ledger = workdir / "session-ledger.json"
        write_json(session_ledger, {"payments": []})
        async with AsyncExitStack() as stack:
            action, action_protocol, action_tools = await open_session(
                stack,
                "action_server.py",
                session_ledger,
            )
            verifier, verifier_protocol, verifier_tools = await open_session(
                stack,
                "verifier_server.py",
                session_ledger,
            )
            if action_protocol != verifier_protocol:
                raise RuntimeError("MCP servers negotiated different protocol versions")
            required_action = {"observe_order", "create_payment", "cancel_payment"}
            if not required_action.issubset(action_tools):
                raise RuntimeError("action server did not expose required tools")
            if "verify_single_payment" not in verifier_tools:
                raise RuntimeError("verifier server did not expose required tool")

            evidence = {
                "action_server_tools": sorted(action_tools),
                "verifier_server_tools": sorted(verifier_tools),
                "independent_server_processes": True,
            }
            bundle = {
                "profile": "org.causal-memory-layer.caep.mcp-sdk-adapter",
                "transport": "mcp-stdio",
                "protocol_version": action_protocol,
                "sdk_package": "mcp",
                "sdk_version": importlib.metadata.version("mcp"),
                "participants": [
                    "urn:mcp-server:payment-writer",
                    "urn:mcp-server:independent-ledger-verifier",
                ],
                "happy_path": await run_happy(
                    workdir,
                    session_ledger,
                    action,
                    verifier,
                    action_protocol,
                    evidence,
                ),
                "recovery_path": await run_recovery(
                    workdir,
                    session_ledger,
                    action,
                    verifier,
                    action_protocol,
                    evidence,
                ),
            }
            validate_caep_bundle(bundle)
            write_json(output, bundle)
            return bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bundle = asyncio.run(run(args.output))
    print(
        json.dumps(
            {
                "caep_validation": "valid",
                "transport": bundle["transport"],
                "protocol_version": bundle["protocol_version"],
                "sdk_version": bundle["sdk_version"],
                "happy": bundle["happy_path"]["verification"]["verdict"],
                "diverged": bundle["recovery_path"]["diverged_verification"]["verdict"],
                "recovered": bundle["recovery_path"]["recovered_verification"]["verdict"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
