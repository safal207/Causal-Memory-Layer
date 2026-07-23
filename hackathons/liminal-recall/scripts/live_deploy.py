from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


APP_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = APP_ROOT / "evidence"
REQUIRED_ENV = ("DATABASE_URL", "COCKROACH_CLUSTER", "AWS_REGION", "STACK_NAME")
REQUIRED_TOOLS = ("aws", "sam", "ccloud", "cockroach")


class DeploymentError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(
    command: list[str],
    *,
    cwd: Path = APP_ROOT,
    env: dict[str, str] | None = None,
    label: str,
) -> subprocess.CompletedProcess[str]:
    print(f"[liminal-recall] {label}")
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "command failed").strip()
        raise DeploymentError(f"{label} failed: {detail[:1200]}") from exc


def _required_environment() -> dict[str, str]:
    missing = [name for name in REQUIRED_ENV if not os.getenv(name)]
    if missing:
        raise DeploymentError(
            "missing required environment variables: " + ", ".join(missing)
        )
    return {name: os.environ[name] for name in REQUIRED_ENV}


def _check_tools() -> dict[str, str]:
    versions: dict[str, str] = {}
    for tool in REQUIRED_TOOLS:
        path = shutil.which(tool)
        if path is None:
            raise DeploymentError(f"required tool not found on PATH: {tool}")
        versions[tool] = path
    return versions


def _json_output(command: list[str], *, label: str) -> Any:
    completed = _run(command, label=label)
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise DeploymentError(f"{label} did not return valid JSON") from exc


def preflight() -> dict[str, Any]:
    values = _required_environment()
    tools = _check_tools()

    identity = _json_output(
        ["aws", "sts", "get-caller-identity", "--output", "json"],
        label="verify AWS identity",
    )
    _run(["ccloud", "auth", "whoami"], label="verify CockroachDB Cloud identity")
    _run(["sam", "validate", "--template-file", "template.yaml"], label="validate SAM template")

    return {
        "checked_at": _utc_now(),
        "tools": tools,
        "aws_account": identity.get("Account"),
        "aws_arn": identity.get("Arn"),
        "aws_region": values["AWS_REGION"],
        "stack_name": values["STACK_NAME"],
        "cockroach_cluster": values["COCKROACH_CLUSTER"],
        "demo_key_configured": bool(os.getenv("DEMO_API_KEY")),
    }


def apply_schema_and_capture_ccloud() -> None:
    values = _required_environment()
    _run(
        [
            "cockroach",
            "sql",
            "--url",
            values["DATABASE_URL"],
            "--file",
            str(APP_ROOT / "schema.sql"),
        ],
        label="apply CockroachDB vector schema",
    )
    _run(
        [
            sys.executable,
            str(APP_ROOT / "scripts" / "ccloud_evidence.py"),
            "--cluster",
            values["COCKROACH_CLUSTER"],
            "--output",
            str(EVIDENCE_DIR / "ccloud-evidence.json"),
        ],
        label="capture redacted ccloud evidence",
    )


def deploy() -> dict[str, str]:
    values = _required_environment()
    demo_key = os.getenv("DEMO_API_KEY", "")
    model_id = os.getenv("EMBEDDING_MODEL_ID", "amazon.titan-embed-text-v2:0")
    dimensions = os.getenv("EMBEDDING_DIMENSIONS", "256")
    threshold = os.getenv("SIMILARITY_THRESHOLD", "0.35")

    _run(["sam", "build", "--no-cached"], label="build AWS SAM application")
    _run(
        [
            "sam",
            "deploy",
            "--stack-name",
            values["STACK_NAME"],
            "--region",
            values["AWS_REGION"],
            "--capabilities",
            "CAPABILITY_IAM",
            "--resolve-s3",
            "--no-confirm-changeset",
            "--no-fail-on-empty-changeset",
            "--parameter-overrides",
            f"ParameterKey=DatabaseUrl,ParameterValue={values['DATABASE_URL']}",
            f"ParameterKey=DemoApiKey,ParameterValue={demo_key}",
            f"ParameterKey=EmbeddingModelId,ParameterValue={model_id}",
            f"ParameterKey=EmbeddingDimensions,ParameterValue={dimensions}",
            f"ParameterKey=SimilarityThreshold,ParameterValue={threshold}",
        ],
        label="deploy Lambda and Bedrock integration",
    )

    stack = _json_output(
        [
            "aws",
            "cloudformation",
            "describe-stacks",
            "--stack-name",
            values["STACK_NAME"],
            "--region",
            values["AWS_REGION"],
            "--output",
            "json",
        ],
        label="read CloudFormation outputs",
    )
    stacks = stack.get("Stacks") or []
    if len(stacks) != 1:
        raise DeploymentError("expected exactly one CloudFormation stack result")
    outputs = {
        item["OutputKey"]: item["OutputValue"]
        for item in stacks[0].get("Outputs", [])
        if "OutputKey" in item and "OutputValue" in item
    }
    try:
        return {
            "function_url": outputs["FunctionUrl"].rstrip("/"),
            "function_name": outputs["FunctionName"],
        }
    except KeyError as exc:
        raise DeploymentError(f"missing CloudFormation output: {exc.args[0]}") from exc


def _request(
    method: str,
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    protected: bool = False,
) -> dict[str, Any]:
    headers = {"content-type": "application/json"}
    if protected and os.getenv("DEMO_API_KEY"):
        headers["x-demo-key"] = os.environ["DEMO_API_KEY"]
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise DeploymentError(f"HTTP {exc.code} from {url}: {detail[:800]}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"request failed for {url}: {type(exc).__name__}") from exc


def _write_json(name: str, value: Any) -> Path:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / name
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def _verify_decision(decision: dict[str, Any], outcome_id: str) -> None:
    failures: list[str] = []
    if decision.get("decision") != "HUMAN_REVIEW":
        failures.append("decision is not HUMAN_REVIEW")
    if outcome_id not in (decision.get("memory_ids") or []):
        failures.append("outcome UUID is missing from memory_ids")
    retrieval = decision.get("retrieval") or {}
    if retrieval.get("mode") != "cockroachdb_vector_cosine":
        failures.append("retrieval mode is not cockroachdb_vector_cosine")
    if retrieval.get("tool") != "distributed_vector_index":
        failures.append("distributed vector index is not reported")
    execution = decision.get("execution") or {}
    if execution.get("status") != "NOT_EXECUTED":
        failures.append("execution status is not NOT_EXECUTED")
    if execution.get("authority") != "advisory_only":
        failures.append("execution authority is not advisory_only")
    if failures:
        raise DeploymentError("; ".join(failures))


def capture_runtime_proof(function_url: str, function_name: str) -> dict[str, Any]:
    values = _required_environment()
    health_before = _request("GET", f"{function_url}/healthz")
    runtime_before = str(health_before.get("runtime_instance_id") or "")
    if not runtime_before:
        raise DeploymentError("health response has no runtime_instance_id")
    _write_json("health-before.json", health_before)

    outcome = _request(
        "POST",
        f"{function_url}/memories",
        protected=True,
        payload={
            "session_id": "payments-agent",
            "kind": "outcome",
            "content": "Refund was sent twice after retry without an idempotency key",
            "tags": ["refund", "payment", "retry"],
            "status": "negative",
            "confidence": 0.98,
        },
    )
    outcome_id = str(outcome.get("id") or "")
    if not outcome_id:
        raise DeploymentError("memory response has no outcome UUID")
    _write_json("outcome.json", outcome)

    decision_payload = {
        "session_id": "payments-agent",
        "proposed_action": "Send the customer reimbursement again",
        "tags": ["customer", "payout"],
    }
    decision_before = _request(
        "POST",
        f"{function_url}/decisions",
        protected=True,
        payload=decision_payload,
    )
    _verify_decision(decision_before, outcome_id)
    _write_json("decision-before-restart.json", decision_before)

    _run(
        [
            "aws",
            "lambda",
            "update-function-configuration",
            "--function-name",
            function_name,
            "--region",
            values["AWS_REGION"],
            "--description",
            f"liminal-recall-restart-proof-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        ],
        label="force fresh Lambda execution environment",
    )
    _run(
        [
            "aws",
            "lambda",
            "wait",
            "function-updated",
            "--function-name",
            function_name,
            "--region",
            values["AWS_REGION"],
        ],
        label="wait for Lambda configuration update",
    )

    health_after: dict[str, Any] | None = None
    runtime_after = runtime_before
    for _ in range(30):
        health_after = _request("GET", f"{function_url}/healthz")
        runtime_after = str(health_after.get("runtime_instance_id") or "")
        if runtime_after and runtime_after != runtime_before:
            break
        time.sleep(2)
    if not health_after or runtime_after == runtime_before:
        raise DeploymentError("Lambda runtime_instance_id did not change after configuration update")
    _write_json("health-after.json", health_after)

    decision_after = _request(
        "POST",
        f"{function_url}/decisions",
        protected=True,
        payload=decision_payload,
    )
    _verify_decision(decision_after, outcome_id)
    if decision_after.get("runtime_instance_id") != runtime_after:
        raise DeploymentError("post-restart decision did not come from the new runtime")
    _write_json("decision-after-restart.json", decision_after)

    manifest = {
        "captured_at": _utc_now(),
        "repository_commit_sha": _run(
            ["git", "rev-parse", "HEAD"],
            label="record exact repository head",
        ).stdout.strip(),
        "aws_region": values["AWS_REGION"],
        "cloudformation_stack": values["STACK_NAME"],
        "lambda_function_name": function_name,
        "lambda_function_url": function_url,
        "cockroach_cluster": values["COCKROACH_CLUSTER"],
        "embedding_model_id": os.getenv(
            "EMBEDDING_MODEL_ID", "amazon.titan-embed-text-v2:0"
        ),
        "negative_outcome_id": outcome_id,
        "decision_memory_id_before": decision_before.get("decision_memory_id"),
        "decision_memory_id_after": decision_after.get("decision_memory_id"),
        "runtime_instance_id_before": runtime_before,
        "runtime_instance_id_after": runtime_after,
        "retrieval_mode": "cockroachdb_vector_cosine",
        "retrieval_tool": "distributed_vector_index",
        "execution_authority": "advisory_only",
        "demo_key_configured": bool(os.getenv("DEMO_API_KEY")),
    }
    _write_json("live-evidence-manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deploy Liminal Recall and capture bounded hackathon evidence."
    )
    parser.add_argument(
        "mode",
        choices=("preflight", "deploy", "capture", "all"),
        help="Operation to perform",
    )
    parser.add_argument("--function-url", help="Required for capture mode")
    parser.add_argument("--function-name", help="Required for capture mode")
    args = parser.parse_args()

    try:
        if args.mode == "preflight":
            _write_json("preflight.json", preflight())
        elif args.mode == "deploy":
            preflight()
            apply_schema_and_capture_ccloud()
            _write_json("deployment-outputs.json", deploy())
        elif args.mode == "capture":
            if not args.function_url or not args.function_name:
                raise DeploymentError("capture mode requires --function-url and --function-name")
            capture_runtime_proof(args.function_url.rstrip("/"), args.function_name)
        else:
            _write_json("preflight.json", preflight())
            apply_schema_and_capture_ccloud()
            outputs = deploy()
            _write_json("deployment-outputs.json", outputs)
            capture_runtime_proof(outputs["function_url"], outputs["function_name"])
    except DeploymentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Evidence directory: {EVIDENCE_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
