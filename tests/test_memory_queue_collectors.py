from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock
from urllib.error import URLError


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / ".github" / "trust-root" / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


def _load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPT_DIR / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


queue_collector = _load_script(
    "test_memory_queue_revalidation_collect",
    "memory_queue_revalidation_collect.py",
)
workbench_collector = _load_script(
    "test_memory_review_workbench_collect",
    "memory_review_workbench_collect.py",
)


class MemoryQueueCollectorHardeningTests(unittest.TestCase):
    def test_queue_repository_validation_rejects_ambiguous_root_before_network(self):
        with mock.patch.object(queue_collector, "GitHubReader") as reader:
            with self.assertRaisesRegex(queue_collector.CollectionError, "owner/name"):
                queue_collector.collect("owner/name/../../repos/other/name", "token")
            reader.assert_not_called()

    def test_queue_repository_validation_rejects_query_and_fragment(self):
        for value in ("owner/name?ref=other", "owner/name#other", "owner/name/extra"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(queue_collector.CollectionError, "owner/name"):
                    queue_collector._repository(value)

    def test_queue_transport_errors_become_structured_collection_errors(self):
        reader = queue_collector.GitHubReader("token")
        with mock.patch.object(
            queue_collector,
            "urlopen",
            side_effect=URLError("dns unavailable"),
        ):
            with self.assertRaisesRegex(queue_collector.CollectionError, "transport failure"):
                reader.get("/repos/owner/name")

    def test_queue_reader_rejects_non_github_absolute_urls(self):
        reader = queue_collector.GitHubReader("token")
        with self.assertRaisesRegex(queue_collector.CollectionError, "api.github.com"):
            reader.get("https://example.test/redirected")

    def test_workbench_repository_validation_rejects_ambiguous_root(self):
        with self.assertRaisesRegex(workbench_collector.WorkbenchCollectionError, "owner/name"):
            workbench_collector._repository("owner/name/../../repos/other/name")

    def test_workbench_current_main_requires_exact_commit_sha(self):
        with self.assertRaisesRegex(
            workbench_collector.WorkbenchCollectionError,
            "40-char lowercase hex SHA",
        ):
            workbench_collector._sha40("main", "intake.current_main_revision")

    def test_workbench_context_coverage_rejects_duplicate_decision_identity(self):
        first = {
            "packet_id": "packet-1",
            "decision_id": "decision-shared",
            "pack_id": "pack-1",
            "proposal_pr": 191,
            "source_pr": 190,
        }
        second = {
            "packet_id": "packet-2",
            "decision_id": "decision-shared",
            "pack_id": "pack-2",
            "proposal_pr": 194,
            "source_pr": 193,
        }
        with self.assertRaisesRegex(
            workbench_collector.WorkbenchCollectionError,
            "duplicate decision_id",
        ):
            workbench_collector._validate_context_coverage([first, second], 2)

    def test_workbench_transport_errors_become_structured_collection_errors(self):
        reader = workbench_collector.GitHubReader("token")
        with mock.patch.object(
            workbench_collector,
            "urlopen",
            side_effect=TimeoutError("timed out"),
        ):
            with self.assertRaisesRegex(
                workbench_collector.WorkbenchCollectionError,
                "transport failure",
            ):
                reader.get("/repos/owner/name")


if __name__ == "__main__":
    unittest.main()
