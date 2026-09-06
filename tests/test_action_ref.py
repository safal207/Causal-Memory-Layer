from cml.integrations.action_ref import (
    ACTION_REF_SCHEME,
    ActionRefNode,
    derive_action_ref,
    validate_action_ref_graph,
)


BASELINE_TIMESTAMP = "2026-06-18T10:40:00.123Z"
BASELINE_DIGEST = "c6fb63e34b2d61446745d86dd90ececf4c321f15e5023f8ffb897e5b0a32a16b"


def _ref(*, scope: str = "search:task-42") -> str:
    return derive_action_ref(
        agent_id="researcher-agent",
        action_type="tool_call",
        scope=scope,
        timestamp=BASELINE_TIMESTAMP,
    )


def test_identical_canonical_metadata_produces_identical_action_ref() -> None:
    first = _ref()
    second = _ref()

    assert first == second
    assert first == BASELINE_DIGEST


def test_changed_metadata_produces_different_action_ref() -> None:
    assert _ref(scope="search:task-42") != _ref(scope="search:task-43")


def test_unresolved_parent_action_ref_is_reported_as_broken_lineage() -> None:
    child = ActionRefNode(
        action_ref=_ref(),
        parent_action_ref="missing-parent-ref",
        action_ref_scheme=ACTION_REF_SCHEME,
    )

    result = validate_action_ref_graph([child])

    assert not result.passed()
    assert [finding.code for finding in result.findings] == [
        "CML-ACTION-REF-MISSING-PARENT"
    ]


def test_integrity_sidecars_do_not_change_structural_result() -> None:
    root_ref = derive_action_ref(
        agent_id="operator",
        action_type="crew_kickoff",
        scope="crew:demo",
        timestamp="2026-06-18T10:40:00.000Z",
    )
    child_ref = _ref()

    plain = [
        ActionRefNode(action_ref=root_ref),
        ActionRefNode(action_ref=child_ref, parent_action_ref=root_ref),
    ]
    with_sidecars = [
        ActionRefNode(
            action_ref=root_ref,
            signature="demo-root-proof",
            anchor="audit-log-entry-1",
        ),
        ActionRefNode(
            action_ref=child_ref,
            parent_action_ref=root_ref,
            signature="demo-child-proof",
            anchor="audit-log-entry-2",
        ),
    ]

    assert validate_action_ref_graph(plain) == validate_action_ref_graph(with_sidecars)
    assert validate_action_ref_graph(plain).passed()
