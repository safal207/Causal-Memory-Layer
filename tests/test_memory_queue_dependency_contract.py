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

    def _workflow_with_install_commands(
        self, commands: list[str], *, extra_steps: list[str] | None = None
    ) -> str:
        return (
            "\n".join(
                [
                    "jobs:",
                    "  test:",
                    "    steps:",
                    "      - name: Run unrelated tests",
                    "        run: |",
                    "          python -m pytest \\",
                    "            tests/test_memory_proposal_queue.py \\",
                    "            tests/test_memory_proposal_queue_revalidation.py",
                    f"      - name: {CONTRACT.INSTALL_STEP_NAME}",
                    "        run: |",
                    *[f"          {command}" for command in commands],
                    *(extra_steps or []),
                ]
            )
            + "\n"
        )

    def test_exact_protected_requirement_commands_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = self._write_workflow(
                root,
                self._workflow_with_install_commands(
                    list(CONTRACT.CANONICAL_INSTALL_COMMANDS),
                    extra_steps=[
                        "      - name: Verify authority boundary",
                        "        run: |",
                        "          python - <<'PY'",
                        "          import json",
                        '          assert json.loads(\'{"authority_granted": false}\')["authority_granted"] is False',
                        "          PY",
                    ],
                ),
            )
            with patch.object(CONTRACT, "ROOT", root):
                CONTRACT._require_hash_enforced_workflow(workflow)

    def test_commented_expected_commands_and_untrusted_suffix_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = self._write_workflow(
                root,
                self._workflow_with_install_commands(
                    [
                        f"# {CONTRACT.CANONICAL_INSTALL_COMMANDS[0]}",
                        f"# {CONTRACT.CANONICAL_INSTALL_COMMANDS[1]}",
                        "python3 -m pip install --require-hashes --only-binary=:all: --requirement .github/trust-root/memory_queue_pip_bootstrap.txt.untrusted",
                    ]
                ),
            )
            with patch.object(CONTRACT, "ROOT", root):
                with self.assertRaisesRegex(
                    CONTRACT.DependencyContractError,
                    "commands must exactly match the protected install contract",
                ):
                    CONTRACT._require_hash_enforced_workflow(workflow)

    def test_dynamic_installer_after_canonical_commands_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = self._write_workflow(
                root,
                self._workflow_with_install_commands(
                    [
                        *CONTRACT.CANONICAL_INSTALL_COMMANDS,
                        "INSTALLER=python",
                        "PIP_MODULE=pip",
                        '"$INSTALLER" -m "$PIP_MODULE" install --require-hashes --only-binary=:all: --requirement .github/trust-root/memory_queue_ci_requirements.txt',
                    ]
                ),
            )
            with patch.object(CONTRACT, "ROOT", root):
                with self.assertRaisesRegex(
                    CONTRACT.DependencyContractError,
                    "commands must exactly match the protected install contract",
                ):
                    CONTRACT._require_hash_enforced_workflow(workflow)

    def test_dynamic_installer_in_separate_step_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = self._write_workflow(
                root,
                self._workflow_with_install_commands(
                    list(CONTRACT.CANONICAL_INSTALL_COMMANDS),
                    extra_steps=[
                        "      - name: Hidden installer",
                        "        run: |",
                        "          PYTHON=python",
                        "          PIP_MODULE=pip",
                        "          SUBCOMMAND=install",
                        '          "$PYTHON" -m "$PIP_MODULE" "$SUBCOMMAND" --no-require-hashes -r attacker.txt',
                    ],
                ),
            )
            with patch.object(CONTRACT, "ROOT", root):
                with self.assertRaisesRegex(
                    CONTRACT.DependencyContractError,
                    "must not construct commands through shell assignments",
                ):
                    CONTRACT._require_hash_enforced_workflow(workflow)

    def test_non_python_shell_command_outside_install_step_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = self._write_workflow(
                root,
                self._workflow_with_install_commands(
                    list(CONTRACT.CANONICAL_INSTALL_COMMANDS),
                    extra_steps=[
                        "      - name: Hidden shell",
                        "        run: |",
                        '          bash -c "$COMMAND"',
                    ],
                ),
            )
            with patch.object(CONTRACT, "ROOT", root):
                with self.assertRaisesRegex(
                    CONTRACT.DependencyContractError,
                    "outside the restricted Python grammar",
                ):
                    CONTRACT._require_hash_enforced_workflow(workflow)


if __name__ == "__main__":
    unittest.main()
