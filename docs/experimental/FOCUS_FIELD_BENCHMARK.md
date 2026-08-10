# Focus–Field Recovery A/B Benchmark v0.1

Status: **experimental / synthetic / deterministic**

This benchmark compares two recovery strategies on identical interrupted causal trajectories:

- **Sequential replay**: rewind history/graph positions until the known recovery point is reached.
- **Focus–Field**: evaluate a bounded set of candidate anchors, rank them using the experimental recovery scorer, and re-anchor without sequential rewind.

The baseline is intentionally given the correct target as an oracle, so it is not disadvantaged on correctness. v0.1 therefore tests **recovery work**, not whether one strategy can infer the target while the other cannot.

## Current deterministic fixtures

| Scenario | Sequential steps | Focus–Field steps | Reduction | Result |
|---|---:|---:|---:|---|
| deep verified re-anchor | 17 | 2 | 88.2% | same correct target |
| value breaks semantic tie | 14 | 2 | 85.7% | same correct target |
| shallow recovery control | 2 | 2 | 0% | same correct target |

Across these fixtures Focus–Field keeps goal and causal consistency and does not select a wrong anchor. The shallow control is intentionally included to show that field recovery is **not claimed to be universally cheaper**.

## What these numbers do and do not mean

These are abstract deterministic recovery steps. They are **not yet measurements of LLM tokens, GPU/CPU usage, wall-clock latency, or production cost**.

The result currently supports only the narrower hypothesis:

> When the relevant recovery point is deep in history but the candidate recovery field is small and well-formed, field-mediated re-anchoring can require fewer recovery operations than sequential rewind.

## Metrics

The benchmark records:

- recovery success;
- wrong-anchor selection;
- recovery steps;
- sequential nodes revisited;
- rewind steps avoided;
- goal-consistency proxy;
- causal-consistency proxy.

## Next validation stage

A stronger v0.2 benchmark should run real agent traces and measure:

1. tokens read/generated during recovery;
2. wall-clock recovery latency;
3. model/tool calls;
4. wrong-anchor rate under noisy candidate fields;
5. goal drift after continued execution;
6. verification success after re-entry;
7. field-construction cost;
8. break-even point where candidate-field scoring becomes more expensive than replay.

That break-even point is essential: Focus–Field should be selected adaptively, not treated as the default for every interruption.

## Files

- `benchmarks/experimental/focus_field_recovery.py`
- `tests/test_focus_field_benchmark.py`
- `cml/experimental/focus_field.py`
