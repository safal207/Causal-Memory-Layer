"""Build the Lambda artifact from an explicit, secret-free source allowlist."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parent
REQUIREMENTS = SOURCE_DIR / "requirements.txt"
RUNTIME_SOURCE_FILES = (
    "__init__.py",
    "embeddings.py",
    "engine.py",
    "handler.py",
    "models.py",
    "store.py",
)


def clean_artifacts(artifacts_dir: Path) -> None:
    """Remove any files SAM staged before the allowlist builder runs."""

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    for path in artifacts_dir.iterdir():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()


def copy_runtime_sources(artifacts_dir: Path) -> None:
    """Copy only Lambda runtime code and the CockroachDB CA certificate."""

    runtime_dir = artifacts_dir / "app"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    for filename in RUNTIME_SOURCE_FILES:
        shutil.copy2(SOURCE_DIR / filename, runtime_dir / filename)
    shutil.copy2(SOURCE_DIR / "cockroach-root.crt", runtime_dir / "cockroach-root.crt")


def build(artifacts_dir: Path) -> None:
    clean_artifacts(artifacts_dir)
    copy_runtime_sources(artifacts_dir)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--requirement",
            str(REQUIREMENTS),
            "--target",
            str(artifacts_dir),
            "--no-compile",
        ],
        check=True,
        cwd=SOURCE_DIR,
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: build_lambda.py ARTIFACTS_DIR")
    build(Path(sys.argv[1]).resolve())
