"""
cml.ctag — Causal Tag (CTAG) computation (v0.4)

16-bit semantic marker:

  b15..b12  DOM   (4 bits) — trust domain
  b11..b8   CLASS (4 bits) — action class
  b7..b4    GEN   (4 bits) — generation/epoch (mod 16)
  b3..b1    LHINT (3 bits) — lineage hint derived from parent_cause
  b0        SEAL  (1 bit)  — chain continuation flag

Reference: vcml/CTAG.md
"""

from __future__ import annotations

import warnings
from typing import Optional


# ---------------------------------------------------------------------------
# DOM table
# ---------------------------------------------------------------------------

class DOM:
    UNKNOWN     = 0
    KERNEL      = 1
    PLATFORM    = 2
    SERVICE     = 3
    USER        = 4
    ADMIN       = 5
    CI_CD       = 6
    TENANT_A    = 7
    TENANT_B    = 8
    TENANT_C    = 9
    SANDBOX     = 10
    UNTRUSTED   = 11
    THIRD_PARTY = 12
    AGENT       = 13
    BREAK_GLASS = 14
    RESERVED    = 15

    _BY_NAME = {
        "UNKNOWN": 0, "KERNEL": 1, "PLATFORM": 2, "SERVICE": 3,
        "USER": 4, "ADMIN": 5, "CI_CD": 6,
        "TENANT_A": 7, "TENANT_B": 8, "TENANT_C": 9,
        "SANDBOX": 10, "UNTRUSTED": 11, "THIRD_PARTY": 12,
        "AGENT": 13, "BREAK_GLASS": 14, "RESERVED": 15,
    }
    _BY_VAL = {v: k for k, v in _BY_NAME.items()}

    @staticmethod
    def name(val: int) -> str:
        return DOM._BY_VAL.get(val, f"DOM({val})")

    @staticmethod
    def from_name(name: str) -> int:
        return DOM._BY_NAME[name.upper()]


# ---------------------------------------------------------------------------
# CLASS table
# ---------------------------------------------------------------------------

class CLASS:
    NONE        = 0
    READ        = 1
    WRITE       = 2
    EXEC        = 3
    NET_OUT     = 4
    NET_IN      = 5
    IPC         = 6
    PRIV        = 7
    CONFIG      = 8
    SECRET      = 9
    CRYPTO      = 10
    FIN_TX      = 11
    DATA_EGRESS = 12
    ML_ACTION   = 13
    OVERRIDE    = 14
    SYSTEM      = 15

    _BY_NAME = {
        "NONE": 0, "READ": 1, "WRITE": 2, "EXEC": 3,
        "NET_OUT": 4, "NET_IN": 5, "IPC": 6, "PRIV": 7,
        "CONFIG": 8, "SECRET": 9, "CRYPTO": 10, "FIN_TX": 11,
        "DATA_EGRESS": 12, "ML_ACTION": 13, "OVERRIDE": 14, "SYSTEM": 15,
    }
    _BY_VAL = {v: k for k, v in _BY_NAME.items()}

    @staticmethod
    def name(val: int) -> str:
        return CLASS._BY_VAL.get(val, f"CLASS({val})")

    @staticmethod
    def from_name(name: str) -> int:
        return CLASS._BY_NAME[name.upper()]

    @staticmethod
    def from_action(action: str) -> int:
        mapping = {
            "exec":    CLASS.EXEC,
            "open":    CLASS.READ,
            "read":    CLASS.READ,
            "write":   CLASS.WRITE,
            "connect": CLASS.NET_OUT,
            "send":    CLASS.NET_OUT,
        }
        return mapping.get(action.lower(), CLASS.NONE)


# ---------------------------------------------------------------------------
# FNV-1a 64-bit
# ---------------------------------------------------------------------------

_FNV_OFFSET = 0xcbf29ce484222325
_FNV_PRIME  = 0x100000001b3
_U64_MASK   = 0xFFFFFFFFFFFFFFFF


def _fnv1a_64(data: str) -> int:
    h = _FNV_OFFSET
    for byte in data.encode("utf-8"):
        h ^= byte
        h = (h * _FNV_PRIME) & _U64_MASK
    return h


# ---------------------------------------------------------------------------
# LHINT formula (canonical v0.4)
# ---------------------------------------------------------------------------

def compute_lhint(parent_cause_id: str, dom: int, cls: int, gen: int) -> int:
    """
    LHINT = (FNV1a64(parent_cause_id) XOR (dom<<4) XOR (cls<<0) XOR (gen<<2)) & 0b111
    """
    h = _fnv1a_64(parent_cause_id)
    return int((h ^ (dom << 4) ^ (cls << 0) ^ (gen << 2)) & 0b111)


# ---------------------------------------------------------------------------
# GEN bump rules
# ---------------------------------------------------------------------------

_GEN_BUMP_ACTIONS = {"exec", "priv"}
_GEN_BUMP_CLASSES = {CLASS.EXEC, CLASS.PRIV}


def should_bump_gen(action: str, cls: int, prev_dom: int, new_dom: int,
                    entering_break_glass: bool = False,
                    warn_on_mismatch: bool = True) -> bool:
    """Determine if the GEN counter should bump.

    Both action string and CLASS enum are checked intentionally: the CLASS
    enum is the authoritative source, but the action string provides a
    fallback when the caller hasn't mapped action→class yet.  A semantic
    contradiction (e.g. action="open" with CLASS.EXEC) indicates a
    misconfigured caller; the bump is still applied to err on the side of
    caution (new generation = more conservative audit trail).

    Args:
        warn_on_mismatch: Emit a ``UserWarning`` when the action string and
            ``cls`` disagree.  Set to ``False`` when the caller intentionally
            overrides the default class mapping (e.g. an "open" that requires
            elevated privileges and is classified as ``CLASS.PRIV``).
    """
    # Validate action/CLASS consistency
    expected_cls = CLASS.from_action(action)
    if warn_on_mismatch and expected_cls != CLASS.NONE and expected_cls != cls:
        warnings.warn(
            f"Action '{action}' maps to {CLASS.name(expected_cls)} but "
            f"cls={CLASS.name(cls)}; possible misconfiguration "
            f"(bump applied conservatively).",
            stacklevel=2,
        )
    if entering_break_glass:
        return True
    if action.lower() in _GEN_BUMP_ACTIONS:
        return True
    if cls in _GEN_BUMP_CLASSES:
        return True
    if prev_dom != new_dom:
        return True
    return False


# ---------------------------------------------------------------------------
# Main CTAG computation
# ---------------------------------------------------------------------------

def compute_ctag(
    dom: int,
    cls: int,
    gen: int,
    parent_cause_id: Optional[str],
    seal: bool = False,
) -> int:
    """
    Compute the 16-bit CTAG value.

    If parent_cause_id is None (root event), LHINT is 0.
    """
    if parent_cause_id is not None:
        lhint = compute_lhint(parent_cause_id, dom, cls, gen)
    else:
        lhint = 0

    seal_bit = 1 if seal else 0

    ctag = (
        ((dom   & 0xF) << 12) |
        ((cls   & 0xF) << 8)  |
        ((gen   & 0xF) << 4)  |
        ((lhint & 0x7) << 1)  |
        seal_bit
    )
    return ctag & 0xFFFF


def decode_ctag(ctag: int) -> dict:
    """Decode a 16-bit CTAG value into its components."""
    dom   = (ctag >> 12) & 0xF
    cls   = (ctag >> 8)  & 0xF
    gen   = (ctag >> 4)  & 0xF
    lhint = (ctag >> 1)  & 0x7
    seal  = ctag & 0x1
    return {
        "raw":       f"0x{ctag:04X}",
        "dom":       dom,
        "dom_name":  DOM.name(dom),
        "class":     cls,
        "class_name": CLASS.name(cls),
        "gen":       gen,
        "lhint":     lhint,
        "seal":      bool(seal),
    }


# ---------------------------------------------------------------------------
# CTAG propagation helper
# ---------------------------------------------------------------------------

class CTAGState:
    """
    Tracks CTAG state across a causal chain.
    Manages GEN bumping and DOM transitions.
    """

    def __init__(self, dom: int = DOM.USER, gen: int = 0):
        self.dom = dom
        self.gen = gen

    def next(
        self,
        action: str,
        cls: int,
        parent_cause_id: Optional[str],
        new_dom: Optional[int] = None,
        seal: bool = False,
    ) -> int:
        target_dom = new_dom if new_dom is not None else self.dom
        if should_bump_gen(action, cls, self.dom, target_dom):
            self.gen = (self.gen + 1) % 16
        self.dom = target_dom

        seal_auto = cls in (CLASS.OVERRIDE,)
        ctag = compute_ctag(
            dom=self.dom,
            cls=cls,
            gen=self.gen,
            parent_cause_id=parent_cause_id,
            seal=seal or seal_auto,
        )
        return ctag
