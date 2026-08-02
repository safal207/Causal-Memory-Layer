from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
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
REQUIRED_ENV = (
    "DATABASE_URL",
    "COCKROACH_CLUSTER",
    "AWS_REGION",
    "STACK_NAME",
    "DEMO_API_KEY",
)
REQUIRED_TOOLS = ("aws", "sam", "ccloud", "cockroach", "git")
_OUTPUT_TAIL_LINES = 12
_OUTPUT_TAIL_CHARS = 2400
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SECRET_ENV_NAME_RE = re.compile(
    r"(?:DATABASE_URL|API[_-]?KEY|ACCESS[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (
        \b(?:
            database[\s_-]*url
            | api[\s_-]*key
            | access[\s_-]*key
            | secret(?:[\s_-]*access)?[\s_-]*key
            | session[\s_-]*token
            | authorization
            | credentials?
            | password
            | token
        )\b
        \s*(?:=|:)\s*
    )
    (?:"[^"]*"|'[^']*'|[^\s,;]+)
    """
)
_SECRET_PARAMETER_RE = re.compile(
    r"(?i)(ParameterKey=(?:DatabaseUrl|DemoApiKey),ParameterValue=)[^\s]+"
)
_URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>{}\[\]\"']+")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_ACCOUNT_ID_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_ENV_LOCAL_RE = re.compile(r"""(?i)(?:[^\s"'<>]*/)?\.env\.local""")


class DeploymentError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact_text(value: str) -> str:
    sanitized = _ANSI_ESCAPE_RE.sub("", value)
    for name, secret in os.environ.items():
        if _SECRET_ENV_NAME_RE.search(name) and len(secret) >= 4:
            sanitized = sanitized.replace(secret, "[REDACTED]")
    sanitized = _SECRET_PARAMETER_RE.sub(r"\1[REDACTED]", sanitized)
    sanitized = _SECRET_ASSIGNMENT_RE.sub(r"\1[REDACTED]", sanitized)
    sanitized = _URL_RE.sub("[REDACTED_URL]", sanitized)
    sanitized = _AWS_ACCESS_KEY_RE.sub("[REDACTED]", sanitized)
    sanitized = _ACCOUNT_ID_RE.sub("[REDACTED_ACCOUNT_ID]", sanitized)
    sanitized = _ENV_LOCAL_RE.sub("[REDACTED_ENV_FILE]", sanitized)
    return sanitized


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _output_tail(value: str | bytes | None) -> str:
    sanitized = _redact_text(_as_text(value))
    lines = [line.strip() for line in sanitized.splitlines() if line.strip()]
    if not lines:
        return "[empty]"
    tail = "\n".join(lines[-_OUTPUT_TAIL_LINES:])
    if len(tail) > _OUTPUT_TAIL_CHARS:
        tail = "[earlier output truncated]\n" + tail[-_OUTPUT_TAIL_CHARS:]
    return tail


def _signal_name(return_code: int) -> str | None:
    if return_code >= 0:
        return None
    try:
        return signal.Signals(-return_code).name
    except ValueError:
        return f"UNKNOWN_SIGNAL_{-return_code}"


def _format_subprocess_failure(
    *,
    label: str,
    return_code: int | None,
    stderr: str | bytes | None,
    stdout: str | bytes | None,
    timeout: float | None = None,
) -> str:
    if return_code is None:
        return_code_text = "unavailable"
    else:
        return_code_text = str(return_code)
    lines = [
        f"command stage: {_redact_text(label)}",
        f"return code: {return_code_text}",
    ]
    if return_code is not None and return_code < 0:
        lines.append(f"signal: {_signal_name(return_code)}")
    if timeout is not None:
        lines.append(f"timeout: {timeout:g} seconds")
    lines.extend(
        (
            "stderr:",
            _output_tail(stderr),
            "final stdout:",
            _output_tail(stdout),
        )
    )
    return "\n".join(lines)


def _run(
    command: list[str],
    *,
    cwd: Path = APP_ROOT,
    env: dict[str, str] | None = None,
    label: str,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    print(f"[liminal-recall] {_redact_text(label)}")
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as exc:
        raise DeploymentError(
            _format_subprocess_failure(
                label=label,
                return_code=exc.returncode,
                stderr=exc.stderr,
                stdout=exc.stdout,
            )
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise DeploymentError(
            _format_subprocess_failure(
                label=label,
                return_code=None,
                stderr=exc.stderr,
                stdout=exc.stdout,
                timeout=float(exc.timeout),
            )
        ) from exc
    except OSError as exc:
        raise DeploymentError(
            _format_subprocess_failure(
                label=label,
                return_code=None,
                stderr=f"{type(exc).__name__}: {exc}",
                stdout=None,
            )
        ) from exc


def _repository_head() -> str:
    head = _run(
        ["git", "rev-parse", "HEAD"],
        label="read exact repository head",
    ).stdout.strip()
    if not _GIT_SHA_RE.fullmatch(head):
        raise DeploymentError("git did not return a full lowercase commit SHA")
    return head


def _require_clean_repository() -> str:
    head = _repository_head()
    status = _run(
        ["git", "status", "--porcelain"],
        label="verify clean repository worktree",
    ).stdout.strip()
    if status:
        raise DeploymentError("repository worktree must be clean before deployment")
    return head


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
    repository_commit_sha = _require_clean_repository()

    identity = _json_output(
        ["aws", "sts", "get-caller-identity", "--output", "json"],
        label="verify AWS identity",
    )
    _run(["ccloud", "auth", "whoami"], label="verify CockroachDB Cloud identity")
    _run(
        ["sam", "validate", "--template-file", "template.yaml"],
        label="validate SAM template",
    )

    return {
        "checked_at": _utc_now(),
        "tools": tools,
        "repository_commit_sha": repository_commit_sha,
        "aws_account": identity.get("Account"),
        "aws_arn": identity.get("Arn"),
        "aws_region": values["AWS_REGION"],
        "stack_name": values["STACK_NAME"],
        "cockroach_cluster": values["COCKROACH_CLUSTER"],
        "demo_key_configured": True,
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
    build_sha = _require_clean_repository()
    model_id = os.getenv("EMBEDDING_MODEL_ID", "amazon.titan-embed-text-v2:0")
    dimensions = os.getenv("EMBEDDING_DIMENSIONS", "256")
    threshold = os.getenv("SIMILARITY_THRESHOLD", "0.35")

    parameter_overrides = [
        f"ParameterKey=DatabaseUrl,ParameterValue={values['DATABASE_URL']}",
        f"ParameterKey=DemoApiKey,ParameterValue={values['DEMO_API_KEY']}",
        f"ParameterKey=BuildSha,ParameterValue={build_sha}",
        f"ParameterKey=EmbeddingModelId,ParameterValue={model_id}",
        f"ParameterKey=EmbeddingDimensions,ParameterValue={dimensions}",
        f"ParameterKey=SimilarityThreshold,ParameterValue={threshold}",
    ]

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
            *parameter_overrides,
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
            "build_sha": build_sha,
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
    if protected:
        demo_key = os.getenv("DEMO_API_KEY", "")
        if not demo_key:
            raise DeploymentError("DEMO_API_KEY is required for protected demo requests")
        headers["x-demo-key"] = demo_key
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = _redact_text(exc.read().decode("utf-8", errors="replace"))
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


def _verify_runtime_build(
    health: dict[str, Any],
    expected_build_sha: str,
    *,
    stage: str,
) -> str:
    if not _GIT_SHA_RE.fullmatch(expected_build_sha):
        raise DeploymentError("expected build SHA is not a full lowercase commit SHA")
    reported_build_sha = str(health.get("build_sha") or "")
    if not _GIT_SHA_RE.fullmatch(reported_build_sha):
        raise DeploymentError(f"{stage} health response has no valid build_sha")
    if reported_build_sha != expected_build_sha:
        raise DeploymentError(f"{stage} Lambda build_sha does not match the reviewed commit")
    return reported_build_sha


def _runtime_proof_payloads() -> tuple[dict[str, Any], dict[str, Any]]:
    return (
        {
            "session_id": "payments-agent",
            "kind": "outcome",
            "content": "Refund was sent twice after retry without an idempotency key",
            "tags": ["duplicate", "payment", "idempotency"],
            "status": "negative",
            "confidence": 0.98,
        },
        {
            "session_id": "payments-agent",
            "proposed_action": "Send the customer reimbursement again",
            "tags": ["customer", "payout"],
        },
    )


def capture_runtime_proof(
    function_url: str,
    function_name: str,
    expected_build_sha: str,
) -> dict[str, Any]:
    values = _required_environment()
    health_before = _request("GET", f"{function_url}/healthz")
    deployed_build_sha = _verify_runtime_build(
        health_before,
        expected_build_sha,
        stage="pre-restart",
    )
    runtime_before = str(health_before.get("runtime_instance_id") or "")
    if not runtime_before:
        raise DeploymentError("health response has no runtime_instance_id")
    _write_json("health-before.json", health_before)

    outcome_payload, decision_payload = _runtime_proof_payloads()
    outcome = _request(
        "POST",
        f"{function_url}/memories",
        protected=True,
        payload=outcome_payload,
    )
    outcome_id = str(outcome.get("id") or "")
    if not outcome_id:
        raise DeploymentError("memory response has no outcome UUID")
    _write_json("outcome.json", outcome)

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
        _verify_runtime_build(
            health_after,
            expected_build_sha,
            stage="post-restart",
        )
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
        "repository_commit_sha": expected_build_sha,
        "deployed_build_sha": deployed_build_sha,
        "aws_region": values["AWS_REGION"],
        "cloudformation_stack": values["STACK_NAME"],
        "lambda_function_name": function_name,
        "lambda_function_url": function_url,
        "cockroach_cluster": values["COCKROACH_CLUSTER"],
        "embedding_model_id": os.getenv(
            "EMBEDDING_MODEL_ID", "amazon.titan-embed-text-v2:0"
        ),
        "embedding_dimensions": 256,
        "negative_outcome_id": outcome_id,
        "decision_memory_id_before": decision_before.get("decision_memory_id"),
        "decision_memory_id_after": decision_after.get("decision_memory_id"),
        "runtime_instance_id_before": runtime_before,
        "runtime_instance_id_after": runtime_after,
        "retrieval_mode": "cockroachdb_vector_cosine",
        "retrieval_tool": "distributed_vector_index",
        "execution_authority": "advisory_only",
        "demo_key_configured": True,
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
    parser.add_argument(
        "--expected-build-sha",
        help="Reviewed commit expected from the deployed /healthz endpoint",
    )
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
            expected_build_sha = args.expected_build_sha or _repository_head()
            capture_runtime_proof(
                args.function_url.rstrip("/"),
                args.function_name,
                expected_build_sha,
            )
        else:
            _write_json("preflight.json", preflight())
            apply_schema_and_capture_ccloud()
            outputs = deploy()
            _write_json("deployment-outputs.json", outputs)
            capture_runtime_proof(
                outputs["function_url"],
                outputs["function_name"],
                outputs["build_sha"],
            )
    except DeploymentError as exc:
        print(f"ERROR: {_redact_text(str(exc))}", file=sys.stderr)
        return 1

    print(f"Evidence directory: {EVIDENCE_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
