from benchmarks.experimental.focus_field_recovery import run_demo


def test_focus_field_matches_target_on_demo_scenarios() -> None:
    results = run_demo()

    assert results
    assert all(result.focus_field.success for result in results)
    assert all(not result.focus_field.wrong_anchor for result in results)
    assert all(result.focus_field.goal_consistent for result in results)
    assert all(result.focus_field.causal_consistent for result in results)


def test_sequential_baseline_is_not_disadvantaged_on_correctness() -> None:
    results = run_demo()

    assert all(result.sequential.success for result in results)
    assert all(not result.sequential.wrong_anchor for result in results)


def test_deep_scenarios_reduce_recovery_steps() -> None:
    by_id = {result.scenario_id: result for result in run_demo()}

    deep = by_id["deep_verified_reanchor"]
    value_tie = by_id["value_breaks_semantic_tie"]

    assert deep.sequential.recovery_steps == 17
    assert deep.focus_field.recovery_steps == 2  # verified-only filters one anchor
    assert deep.step_reduction == 15
    assert deep.step_reduction_ratio > 0.85

    assert value_tie.sequential.recovery_steps == 14
    assert value_tie.focus_field.recovery_steps == 2
    assert value_tie.step_reduction == 12
    assert value_tie.step_reduction_ratio > 0.85


def test_shallow_control_does_not_overclaim_efficiency() -> None:
    by_id = {result.scenario_id: result for result in run_demo()}
    shallow = by_id["shallow_recovery_control"]

    assert shallow.sequential.recovery_steps == 2
    assert shallow.focus_field.recovery_steps == 2
    assert shallow.step_reduction == 0
    assert shallow.step_reduction_ratio == 0.0


def test_field_reports_rewind_steps_avoided() -> None:
    by_id = {result.scenario_id: result for result in run_demo()}

    assert by_id["deep_verified_reanchor"].focus_field.rewind_steps_avoided == 16
    assert by_id["value_breaks_semantic_tie"].focus_field.rewind_steps_avoided == 13
    assert by_id["shallow_recovery_control"].focus_field.rewind_steps_avoided == 1
