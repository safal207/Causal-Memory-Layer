"""
cml.record — Causal Record model (vCML FORMAT v0)

Defines CausalRecord: the minimal semantic unit of causal memory.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, Union


# ---------------------------------------------------------------------------
# Action constants (canonical boundary types)
# ---------------------------------------------------------------------------

class Action:
    EXEC    = "exec"
    OPEN    = "open"
    READ    = "read"
    WRITE   = "write"
    CONNECT = "connect"
    SEND    = "send"


# ---------------------------------------------------------------------------
# Actor
# ---------------------------------------------------------------------------

@dataclass
class Actor:
    pid:  int
    uid:  int
    ppid: Optional[int] = None
    gid:  Optional[int] = None
    comm: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"pid": self.pid, "uid": self.uid}
        if self.ppid is not None:
            d["ppid"] = self.ppid
        if self.gid is not None:
            d["gid"] = self.gid
        if self.comm is not None:
            d["comm"] = self.comm
        return d

    @staticmethod
    def from_dict(d: dict) -> "Actor":
        return Actor(
            pid=d["pid"],
            uid=d["uid"],
            ppid=d.get("ppid"),
            gid=d.get("gid"),
            comm=d.get("comm"),
        )


# ---------------------------------------------------------------------------
# CausalRecord
# ---------------------------------------------------------------------------

@dataclass
class CausalRecord:
    """
    The minimal causal record as defined by vCML FORMAT v0.

    Immutable once created (append-only log semantics).
    """
    id:           str
    timestamp:    int                       # nanoseconds
    actor:        Actor
    action:       str                       # see Action constants
    object:       Union[str, dict]          # path, address, fd, etc.
    permitted_by: str                       # semantic permission reference
    parent_cause: Optional[str] = None      # id of parent causal record
    ctag:         Optional[int] = None      # 16-bit CTAG (v0.4+)
    integrity:    Optional[str] = None      # hash/sig placeholder (v0.5+)

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @staticmethod
    def new(
        actor: Actor,
        action: str,
        object_: Union[str, dict],
        permitted_by: str,
        parent_cause: Optional[str] = None,
        ctag: Optional[int] = None,
    ) -> "CausalRecord":
        return CausalRecord(
            id=str(uuid.uuid4()),
            timestamp=time.time_ns(),
            actor=actor,
            action=action,
            object=object_,
            permitted_by=permitted_by,
            parent_cause=parent_cause,
            ctag=ctag,
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        d: dict = {
            "id":           self.id,
            "timestamp":    self.timestamp,
            "actor":        self.actor.to_dict(),
            "action":       self.action,
            "object":       self.object,
            "permitted_by": self.permitted_by,
            "parent_cause": self.parent_cause,
        }
        if self.ctag is not None:
            d["ctag"] = self.ctag
        if self.integrity is not None:
            d["integrity"] = self.integrity
        return d

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @staticmethod
    def from_dict(d: dict) -> "CausalRecord":
        actor_raw = d["actor"]
        if not isinstance(actor_raw, dict):
            raise ValueError(f"'actor' must be a dict, got {type(actor_raw).__name__}")
        actor = Actor.from_dict(actor_raw)
        return CausalRecord(
            id=d["id"],
            timestamp=d["timestamp"],
            actor=actor,
            action=d["action"],
            object=d["object"],
            permitted_by=d["permitted_by"],
            parent_cause=d.get("parent_cause"),
            ctag=d.get("ctag"),
            integrity=d.get("integrity"),
        )

    @staticmethod
    def from_json(line: str) -> "CausalRecord":
        return CausalRecord.from_dict(json.loads(line))

    # ------------------------------------------------------------------
    # Semantic helpers
    # ------------------------------------------------------------------

    def is_root(self, prefix: str = "root_event:") -> bool:
        """True if this record is an explicit root event.

        Uses the default root_event_prefix ("root_event:").  If your audit
        pipeline uses a custom AuditConfig.root_event_prefix, pass it here:
            record.is_root(prefix=config.root_event_prefix)
        The audit engine always calls cfg.is_root(record) instead, which
        already respects the configured prefix.
        """
        return (
            self.parent_cause is None
            and isinstance(self.permitted_by, str)
            and self.permitted_by.startswith(prefix)
        )


# ---------------------------------------------------------------------------
# Log loader
# ---------------------------------------------------------------------------

def load_jsonl(path: str) -> list[CausalRecord]:
    records = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(CausalRecord.from_json(line))
    return records


def records_to_index(records: list[CausalRecord]) -> dict[str, CausalRecord]:
    return {r.id: r for r in records}
