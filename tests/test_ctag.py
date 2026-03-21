"""Tests for CTAG computation (v0.4)"""

import warnings
import pytest
from cml.ctag import (
    compute_ctag, decode_ctag, compute_lhint,
    DOM, CLASS, CTAGState, should_bump_gen,
    _fnv1a_64,
)


class TestFNV1a:
    def test_known_empty(self):
        # FNV-1a of empty string is the offset basis
        h = _fnv1a_64("")
        assert h == 0xcbf29ce484222325

    def test_deterministic(self):
        h1 = _fnv1a_64("test-uuid-1234")
        h2 = _fnv1a_64("test-uuid-1234")
        assert h1 == h2

    def test_different_inputs(self):
        assert _fnv1a_64("abc") != _fnv1a_64("xyz")


class TestLHINT:
    def test_range(self):
        lhint = compute_lhint("some-uuid", DOM.USER, CLASS.EXEC, 1)
        assert 0 <= lhint <= 7

    def test_deterministic(self):
        uid = "550e8400-e29b-41d4-a716-446655440000"
        l1 = compute_lhint(uid, DOM.USER, CLASS.EXEC, 1)
        l2 = compute_lhint(uid, DOM.USER, CLASS.EXEC, 1)
        assert l1 == l2

    def test_different_parents_differ(self):
        l1 = compute_lhint("parent-a", DOM.USER, CLASS.READ, 0)
        l2 = compute_lhint("parent-b", DOM.USER, CLASS.READ, 0)
        # Not guaranteed to differ but extremely likely
        # Just check range
        assert 0 <= l1 <= 7
        assert 0 <= l2 <= 7


class TestCTAG:
    def test_layout(self):
        ctag = compute_ctag(DOM.USER, CLASS.EXEC, 1, None, seal=False)
        decoded = decode_ctag(ctag)
        assert decoded["dom"] == DOM.USER
        assert decoded["class"] == CLASS.EXEC
        assert decoded["gen"] == 1
        assert decoded["seal"] is False

    def test_seal_bit(self):
        ctag = compute_ctag(DOM.USER, CLASS.EXEC, 0, None, seal=True)
        decoded = decode_ctag(ctag)
        assert decoded["seal"] is True

    def test_seal_off(self):
        ctag = compute_ctag(DOM.KERNEL, CLASS.PRIV, 0, None, seal=False)
        decoded = decode_ctag(ctag)
        assert decoded["seal"] is False

    def test_null_parent_lhint_zero(self):
        ctag = compute_ctag(DOM.USER, CLASS.READ, 0, None)
        decoded = decode_ctag(ctag)
        assert decoded["lhint"] == 0

    def test_with_parent_lhint_set(self):
        ctag = compute_ctag(DOM.USER, CLASS.READ, 0, "some-parent-id")
        decoded = decode_ctag(ctag)
        assert 0 <= decoded["lhint"] <= 7

    def test_dom_name(self):
        ctag = compute_ctag(DOM.KERNEL, CLASS.SYSTEM, 0, None)
        decoded = decode_ctag(ctag)
        assert decoded["dom_name"] == "KERNEL"
        assert decoded["class_name"] == "SYSTEM"

    def test_16bit_range(self):
        ctag = compute_ctag(DOM.BREAK_GLASS, CLASS.OVERRIDE, 15, None, seal=True)
        assert 0 <= ctag <= 0xFFFF

    def test_dom_table_complete(self):
        for val in range(16):
            name = DOM.name(val)
            assert isinstance(name, str)

    def test_class_table_complete(self):
        for val in range(16):
            name = CLASS.name(val)
            assert isinstance(name, str)


class TestCTAGState:
    def test_gen_bumps_on_exec(self):
        state = CTAGState(dom=DOM.USER, gen=0)
        ctag1 = state.next("exec", CLASS.EXEC, parent_cause_id=None)
        assert state.gen == 1

    def test_gen_bumps_on_dom_change(self):
        state = CTAGState(dom=DOM.USER, gen=0)
        ctag1 = state.next("open", CLASS.READ, parent_cause_id=None, new_dom=DOM.SERVICE)
        assert state.gen == 1
        assert state.dom == DOM.SERVICE

    def test_gen_no_bump_on_read(self):
        state = CTAGState(dom=DOM.USER, gen=2)
        state.next("open", CLASS.READ, parent_cause_id=None)
        assert state.gen == 2  # no bump for same dom + read

    def test_gen_wraps_at_16(self):
        state = CTAGState(dom=DOM.USER, gen=15)
        state.next("exec", CLASS.EXEC, parent_cause_id=None)
        assert state.gen == 0  # wraps mod 16


class TestShouldBumpGen:
    def test_exec_bumps(self):
        assert should_bump_gen("exec", CLASS.EXEC, DOM.USER, DOM.USER) is True

    def test_priv_bumps(self):
        assert should_bump_gen("priv", CLASS.PRIV, DOM.USER, DOM.USER) is True

    def test_dom_change_bumps(self):
        assert should_bump_gen("read", CLASS.READ, DOM.USER, DOM.KERNEL) is True

    def test_normal_read_no_bump(self):
        assert should_bump_gen("read", CLASS.READ, DOM.USER, DOM.USER) is False

    def test_break_glass_bumps(self):
        assert should_bump_gen("open", CLASS.READ, DOM.USER, DOM.USER,
                               entering_break_glass=True) is True

    def test_action_class_mismatch_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            # action "exec" maps to CLASS.EXEC, but we pass CLASS.READ
            result = should_bump_gen("exec", CLASS.READ, DOM.USER, DOM.USER)
            assert result is True  # bumps via action string
            assert len(w) == 1
            assert "misconfiguration" in str(w[0].message)

    def test_consistent_action_class_no_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            should_bump_gen("exec", CLASS.EXEC, DOM.USER, DOM.USER)
            # No warning when action and CLASS agree
            assert len(w) == 0
