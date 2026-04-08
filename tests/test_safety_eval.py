from pathlib import Path

import pytest

from cml.safety_eval import load_safety_eval_cases, render_markdown_report, run_safety_eval


def test_fixture_loader_reads_expected_cases() -> None:
    cases = load_safety_eval_cases(Path('benchmarks/fixtures'))
    assert len(cases) == 6
    ids = {case.case_id for case in cases}
    assert 'valid-grounded-secret-net-chain' in ids
    assert 'missing-parent-reference' in ids
    assert 'custom-rule-missing-session-ancestor' in ids


def test_runner_matches_all_cases() -> None:
    results, summary = run_safety_eval(Path('benchmarks/fixtures'))
    assert summary.total_cases == 6
    assert summary.matched_cases == 6
    assert summary.mismatches == 0

    by_id = {result.case_id: result for result in results}
    assert by_id['valid-grounded-secret-net-chain'].predicted_codes == []
    assert by_id['missing-parent-reference'].predicted_codes == ['CML-AUDIT-R1-MISSING_PARENT']
    assert by_id['unmarked-causal-gap'].predicted_codes == ['CML-AUDIT-R2-GAP_NOT_MARKED']
    assert by_id['ambiguous-root-authority'].predicted_codes == ['CML-AUDIT-R4-AMBIGUOUS_ROOT']
    assert by_id['secret-to-network-without-lineage'].predicted_codes == ['CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN']
    assert by_id['custom-rule-missing-session-ancestor'].predicted_codes == ['CML-AUDIT-R5-NET-OUTSIDE-SESSION']


def test_markdown_report_contains_summary() -> None:
    results, summary = run_safety_eval(Path('benchmarks/fixtures'))
    report = render_markdown_report(results, summary)
    assert '# CML Safety-Eval Results' in report
    assert 'Matched cases' in report
    assert 'custom-rule-missing-session-ancestor' in report


@pytest.mark.parametrize(
    'payload, message',
    [
        ('{"description":"x","expected_passed":true,"expected_codes":[],"records":[{"id":"a","timestamp":1,"actor":{"pid":1,"uid":1},"action":"exec","object":"/bin/app","permitted_by":"root_event:init"}]}', 'case_id'),
        ('{"case_id":"x","description":"x","expected_passed":"yes","expected_codes":[],"records":[{"id":"a","timestamp":1,"actor":{"pid":1,"uid":1},"action":"exec","object":"/bin/app","permitted_by":"root_event:init"}]}', 'expected_passed'),
    ],
)
def test_fixture_loader_rejects_invalid_cases(tmp_path: Path, payload: str, message: str) -> None:
    fixture = tmp_path / 'bad.json'
    fixture.write_text(payload, encoding='utf-8')
    with pytest.raises(ValueError, match=message):
        load_safety_eval_cases(tmp_path)
