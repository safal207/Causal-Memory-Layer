from __future__ import annotations

import importlib.util
import re
from pathlib import Path


TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1]
    / "hackathons"
    / "liminal-recall"
    / "template.yaml"
)


def _template() -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8")


def _liminal_recall_function_block() -> str:
    match = re.search(
        r"(?ms)^  LiminalRecallFunction:\n(?P<body>.*?)(?=^Outputs:)",
        _template(),
    )
    assert match is not None, "LiminalRecallFunction definition is missing"
    return match.group("body")


def test_liminal_recall_function_does_not_reserve_account_concurrency() -> None:
    function_block = _liminal_recall_function_block()

    assert not re.search(
        r"(?m)^\s+ReservedConcurrentExecutions:\s*\S+\s*$",
        function_block,
    )


def test_liminal_recall_function_uses_arm64_with_python_312() -> None:
    function_block = _liminal_recall_function_block()

    assert re.search(r"(?m)^\s+Metadata:\n\s+BuildMethod: makefile\s*$", function_block)
    assert re.search(r"(?m)^\s+CodeUri:\s*app\s*$", function_block)
    assert re.search(r"(?m)^\s+Handler:\s*app\.handler\.lambda_handler\s*$", function_block)
    assert re.search(r"(?m)^\s+Runtime:\s*python3\.12\s*$", function_block)
    assert re.search(r"(?m)^\s+Architectures:\n\s+- arm64\s*$", function_block)
    assert "x86_64" not in function_block


def test_template_requires_demo_key_and_exact_build_sha() -> None:
    template = _template()

    demo_key = re.search(
        r"(?ms)^  DemoApiKey:\n(?P<body>.*?)(?=^  [A-Z][A-Za-z]+:|^Resources:)",
        template,
    )
    assert demo_key is not None
    assert "Default:" not in demo_key.group("body")
    assert re.search(r"(?m)^    MinLength:\s*16\s*$", demo_key.group("body"))

    build_sha = re.search(
        r"(?ms)^  BuildSha:\n(?P<body>.*?)(?=^  [A-Z][A-Za-z]+:|^Resources:)",
        template,
    )
    assert build_sha is not None
    assert "^[0-9a-f]{40}$" in build_sha.group("body")

    function_block = _liminal_recall_function_block()
    assert re.search(r"(?m)^\s+DEMO_API_KEY:\s*!Ref DemoApiKey\s*$", function_block)
    assert re.search(r"(?m)^\s+BUILD_SHA:\s*!Ref BuildSha\s*$", function_block)


def test_template_allows_only_schema_backed_embedding_dimension() -> None:
    template = _template()
    dimensions = re.search(
        r"(?ms)^  EmbeddingDimensions:\n(?P<body>.*?)(?=^  [A-Z][A-Za-z]+:|^Resources:)",
        template,
    )

    assert dimensions is not None
    body = dimensions.group("body")
    assert re.search(r"(?m)^    Default:\s*256\s*$", body)
    assert re.search(r"(?m)^    AllowedValues:\n      - 256\s*$", body)
    assert "512" not in body
    assert "1024" not in body


def test_lambda_build_allowlist_excludes_local_secrets_and_keeps_ca_certificate(
    tmp_path: Path,
) -> None:
    project_root = TEMPLATE_PATH.parent
    script_path = project_root / "app" / "build_lambda.py"
    spec = importlib.util.spec_from_file_location("liminal_lambda_builder", script_path)
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    artifacts_dir = tmp_path / "artifact"
    for relative_path in (
        ".env.local",
        ".env.production",
        ".aws/credentials",
        ".aws/config",
        ".venv/bin/python",
        "config/local.yaml",
        "credentials.json",
        "build_lambda.py",
        "requirements.txt",
        "Makefile",
    ):
        staged_path = artifacts_dir / relative_path
        staged_path.parent.mkdir(parents=True, exist_ok=True)
        staged_path.write_text("DATABASE_URL=redacted\nDEMO_API_KEY=redacted\n", encoding="utf-8")

    builder.clean_artifacts(artifacts_dir)
    builder.copy_runtime_sources(artifacts_dir)

    packaged_paths = {
        path.relative_to(artifacts_dir).as_posix()
        for path in artifacts_dir.rglob("*")
        if path.is_file()
    }
    assert packaged_paths == {
        "app/__init__.py",
        "app/embeddings.py",
        "app/engine.py",
        "app/handler.py",
        "app/models.py",
        "app/store.py",
        "app/cockroach-root.crt",
    }
    assert (artifacts_dir / "app" / "cockroach-root.crt").read_bytes() == (
        project_root / "app" / "cockroach-root.crt"
    ).read_bytes()
    assert (project_root / "app" / "requirements.txt").read_bytes() == (
        project_root / "requirements.txt"
    ).read_bytes()
