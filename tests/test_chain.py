"""Tests for chain reconstruction"""

import pytest
from cml.record import CausalRecord, Actor
from cml.chain import reconstruct_chain, has_path, find_root, ancestors


def _rec(id_, parent=None):
    return CausalRecord(
        id=id_,
        timestamp=1_000_000_000,
        actor=Actor(pid=1, uid=0),
        action="exec",
        object="/bin/sh",
        permitted_by="test",
        parent_cause=parent,
    )


def _index(*records):
    return {r.id: r for r in records}


class TestReconstructChain:
    def test_single_root(self):
        r = _rec("a")
        chain = reconstruct_chain("a", _index(r))
        assert [x.id for x in chain] == ["a"]

    def test_two_levels(self):
        a, b = _rec("a"), _rec("b", parent="a")
        chain = reconstruct_chain("b", _index(a, b))
        assert [x.id for x in chain] == ["a", "b"]

    def test_three_levels(self):
        a = _rec("a")
        b = _rec("b", parent="a")
        c = _rec("c", parent="b")
        chain = reconstruct_chain("c", _index(a, b, c))
        assert [x.id for x in chain] == ["a", "b", "c"]

    def test_missing_parent_stops(self):
        b = _rec("b", parent="nonexistent")
        chain = reconstruct_chain("b", _index(b))
        assert [x.id for x in chain] == ["b"]

    def test_cycle_guard(self):
        # Intentionally break the cycle guard: a → b → a (cycle)
        a = _rec("a", parent="b")
        b = _rec("b", parent="a")
        chain = reconstruct_chain("a", _index(a, b))
        # Should not hang; length should be small
        assert len(chain) <= 2


class TestHasPath:
    def test_direct_parent(self):
        a, b = _rec("a"), _rec("b", parent="a")
        assert has_path("b", "a", _index(a, b)) is True

    def test_indirect_ancestor(self):
        a = _rec("a")
        b = _rec("b", parent="a")
        c = _rec("c", parent="b")
        assert has_path("c", "a", _index(a, b, c)) is True

    def test_no_path(self):
        a, b = _rec("a"), _rec("b")
        assert has_path("b", "a", _index(a, b)) is False

    def test_self_is_not_ancestor(self):
        a = _rec("a")
        assert has_path("a", "a", _index(a)) is False  # starts with from_id, checks parents


class TestFindRoot:
    def test_finds_root(self):
        a = _rec("a")
        b = _rec("b", parent="a")
        c = _rec("c", parent="b")
        root = find_root("c", _index(a, b, c))
        assert root.id == "a"

    def test_root_is_itself(self):
        a = _rec("a")
        root = find_root("a", _index(a))
        assert root.id == "a"


class TestAncestors:
    def test_chain_ancestors(self):
        a = _rec("a")
        b = _rec("b", parent="a")
        c = _rec("c", parent="b")
        anc = ancestors("c", _index(a, b, c))
        assert "a" in anc
        assert "b" in anc
        assert "c" in anc
