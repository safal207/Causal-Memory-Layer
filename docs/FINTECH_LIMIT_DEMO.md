# Fintech Limit Recommendation Demo

Status: executable positioning scenario.

## Purpose

This demo illustrates the central CML thesis:

```text
A system may be functionally correct while being causally invalid.
```

The goal is to show that an AI agent can produce a useful or financially reasonable recommendation while violating the authorization lineage or data-scope rules that should govern the workflow.

CML exists to make those failures inspectable.

---

## Scenario

A financial analyst asks an AI assistant whether a customer transaction limit should be increased.

The AI agent has access to:

- approved customer risk profile;
- transaction history summary;
- internal credit policy;
- restricted raw PII fields;
- previous analyst notes.

The governing policy says:

```text
The AI assistant may recommend a limit change only if:

1. A valid analyst request exists.
2. The policy version is active.
3. Only approved risk summary fields are used.
4. Restricted PII fields are not used.
5. Final approval remains with a human analyst.
```

---

# Case A

## Functionally correct but causally invalid

The AI assistant recommends:

```text
Increase customer limit from EUR 5,000 to EUR 8,000.
```

Financially, the recommendation may appear reasonable.

However, the AI agent used a restricted PII field that was outside the allowed policy scope.

Without CML, the workflow may appear successful:

```text
recommendation_generated = true
recommendation_quality = acceptable
policy_reference_present = true
```

With CML, the system detects a causal violation:

```json
{
  "action": "recommend_limit_change",
  "result": "causally_invalid",
  "violation": "DATA_SCOPE_DENIED",
  "used_field": "restricted_raw_pii.income_source_detail",
  "allowed_scope": "risk_summary_only",
  "permitted_by": "policy.credit_risk.v3",
  "parent_cause": "analyst_request.req_219"
}
```

Expected verdict:

```text
BLOCK or AUDIT
```

Explanation:

```text
The recommendation may be useful,
but it was produced through an impermissible causal path.
```

---

# Case B

## Functionally correct and causally valid

The AI assistant recommends:

```text
Increase customer limit from EUR 5,000 to EUR 7,000.
```

This time the agent uses only approved inputs:

- risk score band;
- repayment summary;
- transaction stability summary;
- active policy version;
- valid analyst request.

CML record:

```json
{
  "action": "recommend_limit_change",
  "result": "causally_valid",
  "permitted_by": "policy.credit_risk.v3",
  "parent_cause": "analyst_request.req_219",
  "data_scope": "risk_summary_only",
  "human_approval_required": true
}
```

Expected verdict:

```text
PROCEED
```

Explanation:

```text
The recommendation is not only useful.
It is also permitted, scoped, and auditable.
```

---

# Demo CLI Concept

Potential future command:

```bash
cml demo fintech-limit
```

Expected output:

```text
Scenario: fintech-limit

Case A: functionally_correct_but_causally_invalid
--------------------------------------------------
AI action: recommend_limit_change
Recommendation: increase limit to EUR 8,000
Functional status: PASS
Causal status: FAIL
Violation: DATA_SCOPE_DENIED
Verdict: BLOCK
Reason: restricted PII field used outside allowed policy scope

Case B: functionally_correct_and_causally_valid
-----------------------------------------------
AI action: recommend_limit_change
Recommendation: increase limit to EUR 7,000
Functional status: PASS
Causal status: PASS
Verdict: PROCEED
Reason: valid parent cause, active policy, approved data scope
```

---

# Why this demo matters

This scenario makes the CML distinction concrete:

```text
Operational success does not imply causal legitimacy.
```

The demo also provides a strong reviewer or investor narrative:

- AI systems increasingly operate inside regulated workflows;
- output correctness alone is insufficient;
- authorization lineage and responsibility preservation matter;
- CML makes those properties inspectable.

---

# One-line takeaway

```text
A successful AI action is not necessarily an allowed AI action.
```
