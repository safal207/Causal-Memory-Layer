# CML Pricing & Tiers

Causal Memory Layer is offered under an **Open Core** model:

- **Core SDK** is MIT-licensed and free forever.
- **Pro** and **Enterprise** tiers provide hosted infrastructure, compliance
  tooling, and SLA-backed support.

---

## Tiers

### Community — Free

| Feature | Included |
|---------|----------|
| Core Python SDK (`pip install causal-memory-layer`) | ✅ |
| CLI tool (`cml audit`, `cml chain`, `cml report`) | ✅ |
| All 4 audit rules (R1–R4) | ✅ |
| CTAG computation library | ✅ |
| eBPF monitors (exec, file, net, combined) | ✅ |
| JSONL causal log format | ✅ |
| Local REST API server (self-hosted) | ✅ |
| Community support (GitHub Issues) | ✅ |
| **Records / month** | Unlimited (local) |

---

### Pro — $99 / month per team

Everything in Community, plus:

| Feature | Included |
|---------|----------|
| Hosted Audit API (no infra needed) | ✅ |
| Persistent log storage (30-day retention) | ✅ |
| Webhook alerts on audit FAIL | ✅ |
| Markdown + PDF compliance reports | ✅ |
| Multi-log cross-correlation | ✅ |
| CTAG-enriched chain visualization | ✅ |
| Priority email support (48h SLA) | ✅ |
| **Records / month** | Up to 10M |

---

### Enterprise — Custom pricing

Everything in Pro, plus:

| Feature | Included |
|---------|----------|
| On-premises deployment (Docker / Helm chart) | ✅ |
| Multi-tenant causal domain isolation | ✅ |
| Custom audit rule definitions | ✅ |
| Compliance pack: SOC 2 / GDPR / PCI-DSS evidence | ✅ |
| AI governance audit trail (ML_ACTION chain) | ✅ |
| Fintech causal ledger (FIN_TX chain, audit evidence) | ✅ |
| Custom retention & encryption at rest | ✅ |
| Dedicated support (4h SLA), named CSM | ✅ |
| Integration: SIEM, Splunk, Elastic, Datadog | ✅ |
| **Records / month** | Unlimited |

---

## Compliance Packs (add-ons)

Available for Pro and Enterprise tiers:

| Pack | Price | Coverage |
|------|-------|----------|
| SOC 2 Type II evidence kit | $299 / audit | Causal chain evidence for CC6–CC9 |
| GDPR data egress report | $199 / report | SECRET→NET_OUT audit for DPA filings |
| PCI-DSS causal trace | $299 / audit | FIN_TX + SECRET chain for PCI scope |
| AI Governance pack | $499 / month | ML_ACTION audit for EU AI Act compliance |

---

## Volume Discounts

| Records / month | Discount |
|-----------------|----------|
| 10M–100M        | 20%      |
| 100M–1B         | 35%      |
| 1B+             | Custom   |

---

## FAQ

**Is the SDK always free?**
Yes. The core `cml` Python package (SDK, CLI, local API) is MIT-licensed and
will never require payment.

**Can I self-host the API server?**
Yes. The `api/server.py` FastAPI server is open source. Pro/Enterprise tiers
provide managed hosting and persistence.

**Is there a trial for Enterprise?**
Yes — 30-day full Enterprise trial upon request. Contact: enterprise@causal-memory.dev

---

> CML is infrastructure for meaning. It should be accessible.
> Monetization funds the sustainable development of the layer.
