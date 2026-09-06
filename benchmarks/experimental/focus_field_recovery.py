"""A/B benchmark for sequential replay vs Focus–Field recovery.

This benchmark is deliberately deterministic. It measures recovery work in
abstract steps rather than model tokens or wall-clock time so that CI can
validate the comparison without external services.

v0.2 keeps the original recovery-work comparison but binds trusted recovery
anchors to the current CML applicability and information-quality contracts.
"""

from __future__ import annotations

from dataclasses import dataclass

from cml.experimental.focus_field import RecoveryAnchor, RecoveryQuery, recover
from cml.integrations.information_quality import (
    CompletenessStatus,
    InformationQualityResult,
    QualityReadiness,
    RelevanceStatus,
    SemanticTruthStatus,
)
from cml.integrations.memory_applicability import ApplicabilityResult, ApplicabilityStatus


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    current_depth: int
    target_anchor_id: str
    query: RecoveryQuery
    anchors: tuple[RecoveryAnchor, ...]


@dataclass(frozen=True)
class StrategyResult:
    strategy: str
    selected_anchor_id: str | None
    success: bool
    wrong_anchor: bool
    recovery_steps: int
    nodes_revisited: int
    rewind_steps_avoided: int
    goal_consistent: bool
    causal_consistent: bool
    trusted_continuation: bool


@dataclass(frozen=True)
class Comparison:
    scenario_id: str
    sequential: StrategyResult
    focus_field: StrategyResult

    @property
    def step_reduction(self) -> int:
        return self.sequential.recovery_steps - self.focus_field.recovery_steps

    @property
    def step_reduction_ratio(self) -> float:
        if self.sequential.recovery_steps == 0:
            return 0.0
        return round(self.step_reduction / self.sequential.recovery_steps, 6)


def _applicable() -> ApplicabilityResult:
    return ApplicabilityResult(ApplicabilityStatus.MATCH, ())


def _quality_ready() -> InformationQualityResult:
    return InformationQualityResult(
        semantic_truth=SemanticTruthStatus.SUPPORTED,
        completeness=CompletenessStatus.COMPLETE,
        relevance=RelevanceStatus.RELEVANT,
        readiness=QualityReadiness.READY,
        reasons=(),
    )


def _anchor_by_id(scenario: Scenario, anchor_id: str | None) -> RecoveryAnchor | None:
    if anchor_id is None:
        return None
    for anchor in scenario.anchors:
        if anchor.anchor_id == anchor_id:
            return anchor
    return None


def _goal_consistent(query: RecoveryQuery, anchor: RecoveryAnchor | None) -> bool:
    if anchor is None:
        return False
    if not query.goal_tags:
        return True
    return bool(query.goal_tags & anchor.goal_tags)


def _causal_consistent(query: RecoveryQuery, anchor: RecoveryAnchor | None) -> bool:
    if anchor is None:
        return False
    if not query.causal_tags:
        return True
    return bool(query.causal_tags & anchor.causal_tags)


def sequential_replay(scenario: Scenario) -> StrategyResult:
    """Replay backward until the known recovery anchor is encountered.

    The baseline models a history/graph rewind that must revisit each prior
    position. It intentionally receives the expected target as an oracle so it
    is not disadvantaged on correctness; the comparison is about recovery work.
    The benchmark treats the known target as trusted by construction so the
    baseline comparison remains about traversal cost, not verification policy.
    """

    target = _anchor_by_id(scenario, scenario.target_anchor_id)
    if target is None or target.graph_depth is None:
        steps = scenario.current_depth
        selected = None
    else:
        steps = max(1, scenario.current_depth - target.graph_depth + 1)
        selected = target.anchor_id

    selected_anchor = _anchor_by_id(scenario, selected)
    success = selected == scenario.target_anchor_id
    return StrategyResult(
        strategy="sequential_replay",
        selected_anchor_id=selected,
        success=success,
        wrong_anchor=selected is not None and not success,
        recovery_steps=steps,
        nodes_revisited=steps,
        rewind_steps_avoided=0,
        goal_consistent=_goal_consistent(scenario.query, selected_anchor),
        causal_consistent=_causal_consistent(scenario.query, selected_anchor),
        trusted_continuation=success,
    )


def focus_field_recovery(scenario: Scenario) -> StrategyResult:
    """Score the bounded anchor field and re-enter from the best candidate."""

    decision = recover(scenario.query, scenario.anchors)
    selected = decision.selected_anchor_id
    selected_anchor = _anchor_by_id(scenario, selected)
    success = selected == scenario.target_anchor_id
    steps = len(decision.ranked_candidates)
    return StrategyResult(
        strategy="focus_field",
        selected_anchor_id=selected,
        success=success,
        wrong_anchor=selected is not None and not success,
        recovery_steps=steps,
        nodes_revisited=0,
        rewind_steps_avoided=decision.rewind_steps_saved or 0,
        goal_consistent=_goal_consistent(scenario.query, selected_anchor),
        causal_consistent=_causal_consistent(scenario.query, selected_anchor),
        trusted_continuation=decision.trusted_continuation,
    )


def compare(scenario: Scenario) -> Comparison:
    return Comparison(
        scenario_id=scenario.scenario_id,
        sequential=sequential_replay(scenario),
        focus_field=focus_field_recovery(scenario),
    )


def _trusted_anchor(**kwargs) -> RecoveryAnchor:
    return RecoveryAnchor(
        evidence_refs=(f"proof:{kwargs['anchor_id']}",),
        applicability=_applicable(),
        information_quality=_quality_ready(),
        **kwargs,
    )


def demo_scenarios() -> tuple[Scenario, ...]:
    """Return deterministic long-horizon recovery fixtures."""

    return (
        Scenario(
            scenario_id="deep_verified_reanchor",
            current_depth=24,
            target_anchor_id="node-8",
            query=RecoveryQuery(
                concepts=frozenset({"context", "payment", "idempotency"}),
                value_tags=frozenset({"preserve-user-intent"}),
                goal_tags=frozenset({"finish-payment-verification"}),
                causal_tags=frozenset({"duplicate-request"}),
                phase="verification",
                current_graph_depth=24,
                require_verified=True,
                minimum_score=0.35,
            ),
            anchors=(
                _trusted_anchor(
                    anchor_id="node-8",
                    concepts=frozenset({"context", "payment", "idempotency"}),
                    value_tags=frozenset({"preserve-user-intent"}),
                    goal_tags=frozenset({"finish-payment-verification"}),
                    causal_tags=frozenset({"duplicate-request"}),
                    phase="verification",
                    unresolved=True,
                    graph_depth=8,
                ),
                _trusted_anchor(
                    anchor_id="node-17",
                    concepts=frozenset({"payment", "logging"}),
                    value_tags=frozenset({"maximize-throughput"}),
                    goal_tags=frozenset({"cleanup"}),
                    causal_tags=frozenset({"timeout"}),
                    phase="execution",
                    graph_depth=17,
                ),
                RecoveryAnchor(
                    anchor_id="node-22",
                    concepts=frozenset({"metrics"}),
                    graph_depth=22,
                ),
            ),
        ),
        Scenario(
            scenario_id="value_breaks_semantic_tie",
            current_depth=18,
            target_anchor_id="node-5",
            query=RecoveryQuery(
                concepts=frozenset({"agent", "context"}),
                value_tags=frozenset({"preserve-user-intent", "minimize-replay"}),
                goal_tags=frozenset({"resume-task"}),
                causal_tags=frozenset({"context-loss"}),
                current_graph_depth=18,
                minimum_score=0.20,
            ),
            anchors=(
                _trusted_anchor(
                    anchor_id="node-5",
                    concepts=frozenset({"agent", "context"}),
                    value_tags=frozenset({"preserve-user-intent", "minimize-replay"}),
                    goal_tags=frozenset({"resume-task"}),
                    causal_tags=frozenset({"context-loss"}),
                    unresolved=True,
                    graph_depth=5,
                ),
                RecoveryAnchor(
                    anchor_id="node-14",
                    concepts=frozenset({"agent", "context"}),
                    value_tags=frozenset({"maximize-throughput"}),
                    goal_tags=frozenset({"summarize-task"}),
                    causal_tags=frozenset({"context-loss"}),
                    graph_depth=14,
                ),
            ),
        ),
        Scenario(
            scenario_id="shallow_recovery_control",
            current_depth=10,
            target_anchor_id="node-9",
            query=RecoveryQuery(
                concepts=frozenset({"schema", "validation"}),
                goal_tags=frozenset({"finish-validation"}),
                causal_tags=frozenset({"invalid-payload"}),
                current_graph_depth=10,
                minimum_score=0.20,
            ),
            anchors=(
                _trusted_anchor(
                    anchor_id="node-9",
                    concepts=frozenset({"schema", "validation"}),
                    goal_tags=frozenset({"finish-validation"}),
                    causal_tags=frozenset({"invalid-payload"}),
                    graph_depth=9,
                ),
                RecoveryAnchor(
                    anchor_id="node-4",
                    concepts=frozenset({"authentication"}),
                    goal_tags=frozenset({"authorize"}),
                    causal_tags=frozenset({"missing-token"}),
                    graph_depth=4,
                ),
            ),
        ),
    )


def run_demo() -> tuple[Comparison, ...]:
    return tuple(compare(scenario) for scenario in demo_scenarios())


if __name__ == "__main__":
    for index, result in enumerate(run_demo(), start=1):
        print(
            f"scenario_no={index}",
            f"sequential_steps={result.sequential.recovery_steps}",
            f"field_steps={result.focus_field.recovery_steps}",
            f"step_reduction={result.step_reduction}",
            f"step_reduction_ratio={result.step_reduction_ratio}",
            f"success={result.focus_field.success}",
            f"trusted={result.focus_field.trusted_continuation}",
        )
