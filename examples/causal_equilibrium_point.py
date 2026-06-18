"""Minimal Causal Equilibrium Point example."""

from cml.experimental.equilibrium import (
    CausalEquilibriumSnapshot,
    evaluate_causal_equilibrium,
)


known_refs = {
    "support:approved-budget",
    "counter:capacity-risk",
    "memory:similar-launch",
}

snapshot = CausalEquilibriumSnapshot(
    action_ref="action:launch-project",
    supporting_refs=("support:approved-budget",),
    counter_refs=("counter:capacity-risk",),
    recalled_memory_refs=("memory:similar-launch",),
    require_counterevidence=True,
)

result = evaluate_causal_equilibrium(snapshot, known_refs=known_refs)

print(result.state.value)
for finding in result.findings:
    print(f"{finding.severity.value} {finding.code}: {finding.message}")
