"""
cml.audit — Audit engine (v0.5.1)

Implements read-only causal coherence analysis for vCML logs.
Rules: R1, R2, R3, R4 (see vcml/audit.md)

Audit does NOT block, enforce, or replace security products.
"""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from typing import Optional
from .record import CausalRecord, records_to_index
from .chain import group_by_pid, has_path, ancestors


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity:
    OK   = "OK"
    WARN = "WARN"
    FAIL = "FAIL"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    code:     str
    severity: str
    record_id: str
    message:  str
    chain_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "code":      self.code,
            "severity":  self.severity,
            "record_id": self.record_id,
            "message":   self.message,
        }
        if self.chain_ids:
            d["chain_ids"] = self.chain_ids
        return d


# ---------------------------------------------------------------------------
# Audit configuration
# ---------------------------------------------------------------------------

@dataclass
class AuditConfig:
    root_event_prefix: str = "root_event:"
    secret_classifications: list[str] = field(default_factory=lambda: ["SECRET"])
    secret_path_prefixes: list[str] = field(default_factory=lambda: ["/secrets/"])
    secret_extensions: list[str] = field(default_factory=lambda: [".key", ".pem"])
    net_out_actions: list[str] = field(default_factory=lambda: ["connect", "send"])
    rules_enabled: dict[str, bool] = field(default_factory=lambda: {
        "R1": True, "R2": True, "R3": True, "R4": True
    })

    @staticmethod
    def _apply_raw(cfg: "AuditConfig", raw: dict) -> "AuditConfig":
        cfg.root_event_prefix = raw.get("root_event_prefix", cfg.root_event_prefix)
        s = raw.get("secret", {})
        if "classifications" in s:
            cfg.secret_classifications = s["classifications"]
        if "path_prefixes" in s:
            cfg.secret_path_prefixes = s["path_prefixes"]
        if "extensions" in s:
            cfg.secret_extensions = s["extensions"]
        n = raw.get("net_out", {})
        if "actions" in n:
            cfg.net_out_actions = n["actions"]
        for rule in raw.get("rules", []):
            rid = rule.get("id")
            enabled = rule.get("enabled", True)
            if rid:
                cfg.rules_enabled[rid] = enabled
        return cfg

    @staticmethod
    def from_yaml(path: str) -> "AuditConfig":
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        return AuditConfig._apply_raw(AuditConfig(), raw)

    @staticmethod
    def from_yaml_string(text: str) -> "AuditConfig":
        raw = yaml.safe_load(text) or {}
        return AuditConfig._apply_raw(AuditConfig(), raw)

    def is_secret(self, record: CausalRecord) -> bool:
        obj = record.object
        if isinstance(obj, dict):
            if obj.get("classification") in self.secret_classifications:
                return True
            path = obj.get("path", "")
        else:
            path = str(obj)
        if any(path.startswith(p) for p in self.secret_path_prefixes):
            return True
        if any(path.endswith(e) for e in self.secret_extensions):
            return True
        return False

    def is_net_out(self, record: CausalRecord) -> bool:
        return record.action in self.net_out_actions

    def is_root(self, record: CausalRecord) -> bool:
        return (
            record.parent_cause is None
            and isinstance(record.permitted_by, str)
            and record.permitted_by.startswith(self.root_event_prefix)
        )


# ---------------------------------------------------------------------------
# Audit result
# ---------------------------------------------------------------------------

@dataclass
class AuditResult:
    total:    int = 0
    ok:       int = 0
    warnings: int = 0
    failures: int = 0
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)
        if finding.severity == Severity.OK:
            self.ok += 1
        elif finding.severity == Severity.WARN:
            self.warnings += 1
        elif finding.severity == Severity.FAIL:
            self.failures += 1

    def passed(self) -> bool:
        return self.failures == 0

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total":    self.total,
                "ok":       self.ok,
                "warnings": self.warnings,
                "failures": self.failures,
                "passed":   self.passed(),
            },
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Audit engine
# ---------------------------------------------------------------------------

class AuditEngine:
    def __init__(self, config: Optional[AuditConfig] = None):
        self.config = config or AuditConfig()

    def run(self, records: list[CausalRecord]) -> AuditResult:
        cfg = self.config
        index = records_to_index(records)
        result = AuditResult(total=len(records))

        r1_enabled = cfg.rules_enabled.get("R1", True)
        r2_enabled = cfg.rules_enabled.get("R2", True)
        r3_enabled = cfg.rules_enabled.get("R3", True)
        r4_enabled = cfg.rules_enabled.get("R4", True)

        for record in records:
            # ----------------------------------------------------------
            # R1 — Reference Integrity
            # ----------------------------------------------------------
            if r1_enabled and record.parent_cause is not None:
                if record.parent_cause not in index:
                    result.add(Finding(
                        code="CML-AUDIT-R1-MISSING_PARENT",
                        severity=Severity.FAIL,
                        record_id=record.id,
                        message=(
                            f"parent_cause '{record.parent_cause}' "
                            f"does not exist in the log."
                        ),
                    ))

            # ----------------------------------------------------------
            # R2 / R4 — Gap Marking & Root Identification (mutually exclusive)
            #
            # For null-parent non-root records:
            #   R4 fires when permitted_by looks like a *near-miss* root label
            #       (starts with the root prefix stem but lacks the separator).
            #       Example: "root_event" instead of "root_event:system_boot".
            #   R2 fires for all other unlabeled cases (arbitrary permitted_by
            #       that is not "unobserved_parent" and not a near-miss root).
            # ----------------------------------------------------------
            if record.parent_cause is None and not cfg.is_root(record):
                # Strip the last character (separator) to get the stem.
                # Using slice instead of rstrip() which strips *characters*
                # and would mangle multi-char separators like "::".
                prefix_stem = cfg.root_event_prefix[:-1] if cfg.root_event_prefix else ""
                near_miss = (
                    bool(prefix_stem)
                    and isinstance(record.permitted_by, str)
                    and record.permitted_by != "unobserved_parent"
                    and record.permitted_by.startswith(prefix_stem)
                    and not record.permitted_by.startswith(cfg.root_event_prefix)
                )

                if r4_enabled and near_miss:
                    result.add(Finding(
                        code="CML-AUDIT-R4-AMBIGUOUS_ROOT",
                        severity=Severity.WARN,
                        record_id=record.id,
                        message=(
                            f"Near-miss root label: permitted_by='{record.permitted_by}' "
                            f"looks like '{cfg.root_event_prefix}' but is missing the "
                            f"required separator. Did you mean "
                            f"'{cfg.root_event_prefix}<cause>'?"
                        ),
                    ))
                elif r2_enabled and not near_miss and record.permitted_by != "unobserved_parent":
                    result.add(Finding(
                        code="CML-AUDIT-R2-GAP_NOT_MARKED",
                        severity=Severity.WARN,
                        record_id=record.id,
                        message=(
                            f"Causal gap: parent_cause=null but permitted_by="
                            f"'{record.permitted_by}' (expected 'unobserved_parent')."
                        ),
                    ))

        # ------------------------------------------------------------------
        # R3 — SECRET → NET_OUT Chain
        # ------------------------------------------------------------------
        if r3_enabled:
            by_pid = group_by_pid(records)
            for pid, pid_records in by_pid.items():
                secret_ids: list[str] = []
                for r in pid_records:
                    if cfg.is_secret(r):
                        secret_ids.append(r.id)

                    if cfg.is_net_out(r) and secret_ids:
                        # Precompute ancestor set once per NET_OUT (O(chain_depth))
                        # instead of calling has_path per secret (O(S × depth)).
                        # Exclude r.id itself: ancestors() includes the record
                        # being tested, so a NET_OUT record that is also
                        # classified SECRET would falsely match itself.
                        anc = ancestors(r.id, index) - {r.id}
                        linked = bool(anc & set(secret_ids))
                        if not linked:
                            result.add(Finding(
                                code="CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN",
                                severity=Severity.FAIL,
                                record_id=r.id,
                                message=(
                                    f"NET_OUT '{r.action}' (pid={pid}) "
                                    f"has no causal link to preceding "
                                    f"SECRET access(es): {secret_ids}."
                                ),
                                chain_ids=list(secret_ids),
                            ))

        result.ok = max(0, result.total - result.warnings - result.failures)
        return result
