from cml.integrations.action_ref import (
    ACTION_REF_SCHEME,
    ActionRefNode,
    derive_action_ref,
    validate_action_ref_graph,
)


def _ref(*, scope: str = "search:task-42") -> str:
    return derive_action_ref(
        agent_id="researcher-agent",
        action_type="tool_call",
        scope=scope,
        timestamp_ms=1781779200123,
    )


def test_identical_canonical_metadata_produces_identical_action_ref() -> None:
    first = _ref()
    second = _ref()

    assert first == second
    assert len(first) == 64


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
        timestamp_ms=1781779200000,
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
