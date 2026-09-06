# Focus–Field Recovery A/B Benchmark v0.2

Status: **experimental / synthetic / deterministic**

This benchmark compares two recovery strategies on identical interrupted causal trajectories:

- **Sequential replay**: rewind history/graph positions until the known recovery point is reached.
- **Focus–Field**: evaluate a bounded set of candidate anchors, rank them using the experimental recovery scorer, and re-anchor without sequential rewind.

The baseline is intentionally given the correct target as an oracle, so it is not disadvantaged on correctness. The benchmark tests **recovery work**, not whether one strategy can infer the target while the other cannot.

## v0.2 trust correction

The v0.1 branch used `verified: bool` as its recovery-verification signal. Since that branch was cut, canonical CML added stronger memory-applicability and information-quality contracts.

Trusted Focus–Field target anchors are therefore now explicit current-state controls:

```text
MemoryApplicability == MATCH
AND InformationQuality == READY
AND evidence_refs != empty
```

The A/B efficiency numbers remain comparable, but a selected historical/stale candidate is no longer reported as a trusted continuation merely because it has evidence attached.

## Current deterministic fixtures

| Scenario | Sequential steps | Focus–Field steps | Reduction | Result |
|---|---:|---:|---:|---|
| deep verified re-anchor | 17 | 2 | 88.2% | same correct current-ready target |
| value breaks semantic tie | 14 | 2 | 85.7% | same correct current-ready target |
| shallow recovery control | 2 | 2 | 0% | same correct current-ready target |

Across these fixtures Focus–Field keeps goal and causal consistency and selects a target that is explicitly eligible for trusted continuation. The shallow control is intentionally included to show that field recovery is **not claimed to be universally cheaper**.

## What these numbers do and do not mean

These are abstract deterministic recovery steps. They are **not yet measurements of LLM tokens, GPU/CPU usage, wall-clock latency, production cost, or general model reliability**.

The result supports only the narrower hypothesis:

> When the relevant recovery point is deep in history but the candidate recovery field is small and well-formed, field-mediated re-anchoring can require fewer recovery operations than sequential rewind while current-state trust eligibility is checked separately.

## Metrics

The benchmark records:

- recovery success;
- wrong-anchor selection;
- recovery steps;
- sequential nodes revisited;
- rewind steps avoided;
- goal-consistency proxy;
- causal-consistency proxy;
- trusted-continuation state for the selected Focus–Field anchor.

## FCRP-SELF-006 regression

The dedicated unit tests additionally prove that:

1. a stale `REVALIDATE` memory is filtered when `require_verified=true`;
2. an `EXCLUDE` information-quality result is filtered;
3. a current `MATCH + READY` anchor remains eligible;
4. a stale historical anchor may still be selected for exploratory context when strict verification is disabled, but it returns `reanchored_exploratory` and `trusted_continuation=false`;
5. missing current gate results are not treated as equivalent to the old `verified=true` contract.

## Next validation stage

A stronger benchmark should run real agent traces and measure:

1. tokens read/generated during recovery;
2. wall-clock recovery latency;
3. model/tool calls;
4. wrong-anchor rate under noisy candidate fields;
5. goal drift after continued execution;
6. verification success after re-entry;
7. field-construction cost;
8. current-state revalidation cost;
9. break-even point where candidate-field scoring becomes more expensive than replay.

That break-even point is essential: Focus–Field should be selected adaptively, not treated as the default for every interruption.

## Files

- `benchmarks/experimental/focus_field_recovery.py`
- `tests/test_focus_field_benchmark.py`
- `tests/test_focus_field.py`
- `cml/experimental/focus_field.py`
- `benchmarks/experimental/fcrp-self-006.json`
