# External Review Note — Action-Reference Reproduction Path

**Reviewer:** `@giskard09`  
**Source date:** 2026-06-20  
**Source discussion:** Causal-Memory-Layer issue #155  
**Evidence level:** public reviewer feedback, not a completed full external-validation report.

## Reported observation

The reviewer reported that the public runner looked clean and that the portable contract made the reproduction path straightforward.

They identified the fixture-chain `action_ref` values as an independently checkable boundary: when the conformance runner emits `action_ref` fields, a third party can compare them with the canonical vectors under `examples/conformance/cml/`.

## Narrow interpretation

This supports only the following statements:

- an external reviewer found the runner and contract understandable;
- the `action_ref` comparison path is described concretely enough for cross-spec review;
- canonical vectors provide a public comparison surface.

## Non-claims

This note does not establish:

- completion of the full external-validation protocol;
- a recorded clean-environment installation, test, benchmark, or Docker run;
- production security, safety, compliance, or complete causal correctness;
- formal certification or organizational endorsement.

The causal-equilibrium semantics remain defined by CML. Agreement with a canonical `action_ref` vector does not by itself validate every upstream semantic assumption.

## Follow-up for stronger evidence

A full validation note should additionally record:

- repository commit SHA;
- operating system and Python version;
- exact commands executed;
- test and benchmark outputs;
- reproduction problems or mismatches;
- independently recomputed `action_ref` results.

See [`../EXTERNAL_VALIDATION_PROTOCOL.md`](../EXTERNAL_VALIDATION_PROTOCOL.md) for the complete reporting format.
