from pathlib import Path

from cml.safety_eval import render_markdown_report, run_safety_eval


def test_tracked_results_snapshot_is_in_sync() -> None:
    results, summary = run_safety_eval(Path('benchmarks/fixtures'))
    expected = render_markdown_report(results, summary)
    tracked = Path('benchmarks/RESULTS.md').read_text(encoding='utf-8')
    assert tracked == expected
