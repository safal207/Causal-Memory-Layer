"""Generate deterministic synthetic CML traces for performance benchmarks.

The generator is intentionally dependency-light and uses the public CML record
model directly. It creates mostly valid causal chains with periodic broken
parent references so the benchmark exercises both normal indexing and R1
finding generation.

Example:

    python benchmarks/performance/generate_large_trace.py \
        --records 10000 \
        --missing-parent-every 997 \
        --output /tmp/cml-large-trace.jsonl
"""

from __future__ import annotations

import argparse
from pathlib import Path

from cml.record import Actor, CausalRecord

ACTIONS = ("read", "write", "exec", "connect", "send")


def make_actor(index: int) -> Actor:
    """Return a deterministic synthetic actor for a trace record."""

    agent_index = index % 16
    return Actor(
        pid=10_000 + agent_index,
        uid=1_000,
        ppid=9_999,
        comm=f"synthetic_agent_{agent_index}",
    )


def make_record(index: int, missing_parent_every: int) -> CausalRecord:
    """Create one deterministic CML record.

    Record 0 is a valid root event. Later records usually point to the previous
    record, except periodic records that intentionally point to a missing
    parent to exercise R1-MISSING_PARENT at predictable intervals.
    """

    record_id = f"record-{index:08d}"

    if index == 0:
        parent_cause = None
        permitted_by = "root_event:large_trace_benchmark"
        action = "approve_task"
        object_ = {"benchmark": "large_trace", "kind": "root"}
    else:
        should_break_parent = (
            missing_parent_every > 0
            and index % missing_parent_every == 0
        )
        parent_cause = (
            f"missing-parent-{index:08d}"
            if should_break_parent
            else f"record-{index - 1:08d}"
        )
        permitted_by = f"task:synthetic_step_{index:08d}"
        action = ACTIONS[index % len(ACTIONS)]
        object_ = {
            "resource": f"synthetic-resource-{index % 128}",
            "step": index,
        }

    return CausalRecord(
        id=record_id,
        timestamp=index + 1,
        actor=make_actor(index),
        action=action,
        object=object_,
        permitted_by=permitted_by,
        parent_cause=parent_cause,
    )


def generate_records(total_records: int, missing_parent_every: int) -> list[CausalRecord]:
    """Generate a deterministic synthetic trace."""

    if total_records < 1:
        raise ValueError("total_records must be >= 1")
    return [make_record(i, missing_parent_every) for i in range(total_records)]


def expected_missing_parent_findings(total_records: int, missing_parent_every: int) -> int:
    """Return the expected number of R1 findings for the generated trace."""

    if total_records < 1:
        return 0
    if missing_parent_every <= 0:
        return 0
    # Index 0 is the root and is never broken.
    return (total_records - 1) // missing_parent_every


def write_jsonl(records: list[CausalRecord], output: Path) -> None:
    """Write generated records as JSONL."""

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(record.to_jsonl())
            f.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, required=True)
    parser.add_argument("--missing-parent-every", type=int, default=997)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    records = generate_records(args.records, args.missing_parent_every)
    write_jsonl(records, args.output)

    expected = expected_missing_parent_findings(
        args.records,
        args.missing_parent_every,
    )
    print(
        "Generated synthetic CML trace: "
        f"records={args.records}, "
        f"missing_parent_every={args.missing_parent_every}, "
        f"expected_r1_findings={expected}, "
        f"output={args.output}"
    )


if __name__ == "__main__":
    main()
