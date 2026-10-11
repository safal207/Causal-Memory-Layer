"""Run the bounded native controls against an immutable clean source checkout."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

SOURCE_SHA = "b7ad69afda6b6ed030347c66d48a13e4de9dec08"
PACKET = Path(__file__).resolve().parent


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()


def source_check(source):
    if git(source, "rev-parse", "HEAD") != SOURCE_SHA:
        raise SystemExit("source identity mismatch")
    if git(source, "status", "--porcelain", "--untracked-files=all"):
        raise SystemExit("source checkout is dirty")
    bindings = json.loads((PACKET / "source-bindings.json").read_text())
    for artifact in bindings["files"]:
        raw = (source / artifact["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
            raise SystemExit("source file binding mismatch: " + artifact["path"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    if args.output.exists():
        raise SystemExit("refusing to overwrite retained evidence")
    source_check(source)
    attempt = str(uuid.uuid4())
    start = datetime.now(UTC).isoformat()
    with tempfile.TemporaryDirectory(prefix="mem0-mutation-clock-") as temporary:
        directory = Path(temporary)
        raw_report = directory / "fixture.json"
        junit = directory / "junit.xml"
        env = os.environ.copy()
        env.update(
            {
                "PYTHONPATH": str(source),
                "PYTHONDONTWRITEBYTECODE": "1",
                "MEM0_SOURCE": str(source),
                "MEM0_TELEMETRY": "false",
                "MEM0_DIR": str(directory / "mem0-home"),
                "MEM0_ATTEMPT_ID": attempt,
                "MEM0_EVIDENCE_OUTPUT": str(raw_report),
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            }
        )
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "pytest_asyncio.plugin",
            "-p",
            "no:cacheprovider",
            str(PACKET / "test_mutation_clock.py"),
            "--junitxml",
            str(junit),
        ]
        completed = subprocess.run(
            command, cwd=PACKET, env=env, text=True, capture_output=True, timeout=120, check=False
        )
        print(completed.stdout, end="")
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, end="")
        if completed.returncode:
            raise SystemExit(completed.returncode)
        suites = ET.parse(junit).getroot().findall("testsuite")
        counts = {
            key: sum(int(suite.attrib.get(key, "0")) for suite in suites)
            for key in ("tests", "failures", "errors", "skipped")
        }
        if counts != {"tests": 2, "failures": 0, "errors": 0, "skipped": 0}:
            raise SystemExit("incomplete native execution: " + repr(counts))
        report = json.loads(raw_report.read_text())
        source_check(source)
        if report["attempt_id"] != attempt or report["source_sha"] != SOURCE_SHA or report["pass_count"] != 2:
            raise SystemExit("fixture evidence identity mismatch")
        versions = {dist.metadata["Name"]: dist.version for dist in importlib.metadata.distributions()}
        report["execution"] = {
            "started_at": start,
            "completed_at": datetime.now(UTC).isoformat(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "dependency_manager": "Hatch detached environment",
            "installed_versions": dict(sorted(versions.items())),
            "junit_counts": counts,
            "exit_code": completed.returncode,
            "source_initial_sha": SOURCE_SHA,
            "source_final_sha": git(source, "rev-parse", "HEAD"),
            "source_worktree": "CLEAN",
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "process_isolation": "fresh pytest subprocess",
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2, ensure_ascii=False)
            output.write("\n")
    print("PASS_WITHIN_BOUND: 2 native controls; clean exact source")


if __name__ == "__main__":
    main()
