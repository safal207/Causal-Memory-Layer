from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".github/trust-root/scripts/verify_memory_queue_dependency_contract.py"
)
SPEC = importlib.util.spec_from_file_location("memory_queue_dependency_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)


class MemoryQueueDependencyContractTests(unittest.TestCase):
    def _write_workflow(self, root: Path, content: str) -> Path:
        path = Path(".github/workflows/test-memory-queue.yml")
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return path

    def test_exact_protected_requirement_commands_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = self._write_workflow(
                root,
                "\n".join(
                    [
                        "python -m pip install --require-hashes --only-binary=:all: --requirement .github/trust-root/memory_queue_pip_bootstrap.txt",
                        "python -m pip install --require-hashes --only-binary=:all: --requirement .github/trust-root/memory_queue_ci_requirements.txt",
                    ]
                )
                + "\n",
            )
            with patch.object(CONTRACT, "ROOT", root):
                CONTRACT._require_hash_enforced_workflow(workflow)

    def test_commented_expected_commands_and_untrusted_suffix_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = self._write_workflow(
                root,
                "\n".join(
                    [
                        "# python -m pip install --require-hashes --only-binary=:all: --requirement .github/trust-root/memory_queue_pip_bootstrap.txt",
                        "# python -m pip install --require-hashes --only-binary=:all: --requirement .github/trust-root/memory_queue_ci_requirements.txt",
                        "python3 -m pip install --require-hashes --only-binary=:all: --requirement .github/trust-root/memory_queue_pip_bootstrap.txt.untrusted",
                    ]
                )
                + "\n",
            )
            with patch.object(CONTRACT, "ROOT", root):
                with self.assertRaisesRegex(
                    CONTRACT.DependencyContractError,
                    "noncanonical pip installer command",
                ):
                    CONTRACT._require_hash_enforced_workflow(workflow)


if __name__ == "__main__":
    unittest.main()
