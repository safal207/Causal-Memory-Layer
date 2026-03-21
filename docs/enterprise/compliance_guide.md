# CML Enterprise Compliance Guide

This guide explains how Causal Memory Layer generates audit evidence for
common compliance frameworks using causal chain analysis.

---

## Overview

CML audit produces **causal chain evidence** — a structured record of:
- *who* acted
- *what* boundary was crossed
- *why* it was permitted
- *what* preceded it causally

This maps directly to the evidence requirements of modern compliance frameworks.

---

## SOC 2 Type II

### Relevant Trust Services Criteria

| Criterion | CML Evidence |
|-----------|-------------|
| CC6.1 — Logical access controls | `permitted_by` field tracks authorization source per action |
| CC6.3 — Access removal | Audit detects orphaned chains after principal deactivation |
| CC7.2 — Anomaly detection | R3 rule detects SECRET→NET_OUT without causal chain |
| CC8.1 — Change management | `root_event:change_request:*` links state changes to tickets |
| CC9.2 — Risk mitigation | CTAG DOM separation documents trust zone transitions |

### Generating SOC 2 Evidence

```bash
# Run audit on production causal log
cml audit production.jsonl --format markdown --config soc2_config.yaml \
  --output soc2_evidence_$(date +%Y%m).md

# Or via API
curl -X POST https://api.causal-memory.dev/audit \
  -H "Authorization: Bearer $CML_TOKEN" \
  -d @production.jsonl > soc2_evidence.json
```

---

## GDPR — Data Egress Audit

### Article 32 — Security of Processing

CML directly addresses Art. 32(1)(b): *"the ability to ensure ongoing
confidentiality, integrity, availability and resilience of processing systems"*.

The R3 rule (`CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN`) detects personal data
flows (classified as `SECRET`) that reach a network destination without a
documented causal chain — exactly the scenario GDPR requires evidence for.

### Data Subject Rights (Art. 15 / 17)

The `cml chain` command reconstructs the full causal history for any record:

```bash
# Find all causal ancestors of a data egress event
cml chain production.jsonl <NET_OUT_record_id>
```

This produces a documented audit trail for DSAR (Data Subject Access Request)
responses and for demonstrating data deletion compliance.

---

## PCI-DSS v4

### Requirement 10 — Audit Logs

| PCI-DSS 10.x | CML Coverage |
|--------------|-------------|
| 10.2.1 — Log all individual access to cardholder data | `open`/`read` events on `FIN_TX`-classified objects |
| 10.2.2 — Log all actions taken by root or privileged users | CTAG `DOM=ADMIN`, `CLASS=PRIV` records |
| 10.2.4 — Invalid logical access attempts | R1 `MISSING_PARENT` (broken chain = unauthorized attempt) |
| 10.3 — Protect log files | Append-only JSONL + integrity field (v0.5+) |

### FIN_TX Chain Rule

For PCI scope, extend `audit_config.yaml`:

```yaml
custom_rules:
  - id: R5-FIN_TX
    description: "FIN_TX operations must have causal chain to authenticated session"
    trigger_class: FIN_TX
    require_ancestor_class: EXEC
    require_ancestor_permitted_by_prefix: "root_event:session:"
    severity: FAIL
    code: CML-AUDIT-R5-FIN_TX_NO_SESSION
```

---

## EU AI Act (Annex IV — Technical Documentation)

CML's `ML_ACTION` CLASS is designed for AI governance:

| AI Act Requirement | CML Evidence |
|--------------------|-------------|
| Art. 13 — Transparency | `ML_ACTION` records document every AI-influenced decision |
| Art. 14 — Human oversight | `BREAK_GLASS` records mark human override of AI decisions |
| Art. 17 — Quality management | Causal chain links training data access to model output |
| Annex IV §2 — Design choices | `permitted_by` records the authorization for each ML step |

```jsonl
{"action":"ml_action","object":{"model":"risk-scorer-v3","input_hash":"sha256:...","decision":"deny_loan"},"permitted_by":"model:risk-scorer-v3:v3.2.1","parent_cause":"<user_data_read_id>","ctag":3840}
```

---

## Generating Compliance Reports

```bash
# SOC 2 Markdown report
cml report production.jsonl --config soc2_config.yaml -o soc2_report.md

# GDPR egress summary
cml audit production.jsonl --format json | \
  jq '[.findings[] | select(.code == "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN")]'

# Validate before a release
cml validate production.jsonl && echo "Causal integrity: PASS"
```

---

## Contact

For custom compliance configuration, enterprise onboarding, or audit
interpretation assistance: **compliance@causal-memory.dev**
