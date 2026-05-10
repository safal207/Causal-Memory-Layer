# Hosted Audit API MVP

**Status:** Draft MVP contract  
**Current implementation reference:** `api/server.py`  
**Target audience:** pilot partners, contributors, enterprise AI governance teams, security reviewers, and API implementers.

CML already includes a FastAPI server for local/community use. This document defines a narrow hosted-service contract that can evolve from the current API without claiming that a production hosted service is already deployed.

## Purpose

The Hosted Audit API should answer one practical question:

> Can a team submit a causal log and receive a reproducible audit result that identifies causal-lineage findings?

The MVP should be small, inspectable, and evidence-oriented. It should not try to become a general workflow engine, SIEM, policy platform, or long-term data lake.

## Existing local API surface

The current FastAPI implementation exposes these local endpoints:

| Current endpoint | Purpose |
|---|---|
| `POST /audit` | Audit raw JSONL text. |
| `POST /audit/file` | Audit uploaded JSONL file. |
| `POST /ingest` | Store records under a named log. |
| `GET /records/{log_name}` | List stored records. |
| `GET /records/{log_name}/audit` | Audit stored records. |
| `GET /chain/{log_name}/{record_id}` | Reconstruct causal chain for a record. |
| `POST /ctag/decode` | Decode a 16-bit CTAG value. |
| `GET /health` | Health check. |

The hosted MVP should expose a stable `/v1` contract while reusing the same underlying audit semantics.

## MVP endpoints

| Hosted endpoint | Purpose | Current local analogue |
|---|---|---|
| `POST /v1/audit/log` | Audit JSONL content sent in the request body. | `POST /audit` |
| `POST /v1/audit/file` | Audit uploaded JSONL file. | `POST /audit/file` |
| `GET /v1/audit/runs/{run_id}` | Fetch stored audit result for a submitted run. | New hosted layer over result store. |
| `GET /v1/health` | Health check. | `GET /health` |

Optional later endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /v1/ingest` | Store records for later audit. |
| `GET /v1/records/{log_name}` | List stored records. |
| `GET /v1/chain/{log_name}/{record_id}` | Reconstruct chain for stored records. |
| `POST /v1/ctag/decode` | Decode CTAG values. |

## Documentation & Examples

For practical integration tests and request/response validation, see:
- [Verified cURL Examples](HOSTED_AUDIT_API_CURL_EXAMPLES.md)
## Authentication

MVP assumption:

```http
Authorization: Bearer <token>
```

The local API already supports bearer-token auth through `CML_API_TOKEN`. A hosted service should require auth by default.

Unauthenticated access may be acceptable only for:

- `GET /v1/health`
- documentation pages if intentionally public

## Endpoint: `POST /v1/audit/log`

Audit JSONL content submitted directly in JSON.

### Request

```http
POST /v1/audit/log
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "log": "{\"id\":\"r1\",\"action\":\"...\"}\n{\"id\":\"r2\",\"parent\":\"r1\"}",
  "config": "optional: yaml audit config",
  "format": "json",
  "store_result": true,
  "metadata": {
    "project_id": "demo-project",
    "source": "ci",
    "environment": "staging"
  }
}
```

### Fields

| Field | Required | Notes |
|---|---:|---|
| `log` | yes | Raw JSONL causal log content. |
| `config` | no | Optional YAML audit configuration. |
| `format` | no | `json`, `markdown`, or `text`; hosted MVP should default to `json`. |
| `store_result` | no | If true, store result temporarily and return `run_id`. |
| `metadata` | no | Non-sensitive caller metadata. |

### Response

```json
{
  "run_id": "run_01HZXAMPLE",
  "status": "completed",
  "summary": {
    "record_count": 12,
    "finding_count": 2,
    "passed": false
  },
  "findings": [
    {
      "code": "CML-AUDIT-R1-MISSING_PARENT",
      "severity": "high",
      "record_id": "r7",
      "message": "Record references a missing parent cause.",
      "details": {
        "missing_parent_id": "r6"
      }
    }
  ],
  "artifacts": {
    "json": "/v1/audit/runs/run_01HZXAMPLE",
    "markdown": null
  }
}
```

## Endpoint: `POST /v1/audit/file`

Audit an uploaded JSONL file.

### Request

```http
POST /v1/audit/file
Authorization: Bearer <token>
Content-Type: multipart/form-data
```

Form fields:

| Field | Required | Notes |
|---|---:|---|
| `file` | yes | JSONL file. |
| `config` | no | Optional YAML config. |
| `store_result` | no | Whether to store result temporarily. |
| `metadata` | no | Optional JSON metadata string. |

### Response

Same response shape as `POST /v1/audit/log`.

## Endpoint: `GET /v1/audit/runs/{run_id}`

Fetch a stored audit result.

### Request

```http
GET /v1/audit/runs/run_01HZXAMPLE
Authorization: Bearer <token>
```

### Response

```json
{
  "run_id": "run_01HZXAMPLE",
  "status": "completed",
  "created_at": "2026-05-10T10:00:00Z",
  "expires_at": "2026-05-11T10:00:00Z",
  "summary": {
    "record_count": 12,
    "finding_count": 2,
    "passed": false
  },
  "findings": [
    {
      "code": "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN",
      "severity": "critical",
      "record_id": "net_egress_1",
      "message": "Network egress follows secret access without valid causal linkage."
    }
  ]
}
```

## Endpoint: `GET /v1/health`

Health check endpoint.

### Response

```json
{
  "status": "ok",
  "version": "0.4.0"
}
```

## Finding codes

The hosted MVP should preserve existing CML audit finding codes. Current benchmark-covered examples include:

| Code | Meaning |
|---|---|
| `CML-AUDIT-R1-MISSING_PARENT` | A record references a missing parent cause. |
| `CML-AUDIT-R2-GAP_NOT_MARKED` | A causal gap exists but is not explicitly marked. |
| `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN` | Secret-to-network behavior lacks valid causal lineage. |
| `CML-AUDIT-R4-AMBIGUOUS_ROOT` | Root authority is ambiguous or malformed. |
| `CML-AUDIT-R5-NET-OUTSIDE-SESSION` | Custom rule: network action outside expected session ancestry. |

## Error model

| HTTP status | Meaning | Example |
|---:|---|---|
| `400` | Bad request shape. | Missing required field. |
| `401` | Missing or invalid token. | Bad bearer token. |
| `413` | Payload too large. | JSONL file exceeds configured limit. |
| `422` | Parse or validation error. | Invalid JSONL record. |
| `429` | Rate limit exceeded. | Too many audit requests. |
| `500` | Internal error. | Unexpected audit failure. |

Example error:

```json
{
  "error": {
    "code": "INVALID_JSONL",
    "message": "Failed to parse record at line 17.",
    "details": {
      "line": 17
    }
  }
}
```

## Storage and privacy assumptions

A hosted CML API should use minimal retention by default.

MVP assumptions:

- Raw logs are not stored permanently by default.
- Stored audit results have a TTL.
- Caller metadata should not contain secrets.
- Sensitive payloads should be redacted before upload when possible.
- Result storage should be explicitly controlled by `store_result` or service policy.
- Operators must document whether raw logs, derived findings, or both are retained.

Recommended environment controls based on the current local API:

| Env var | Purpose |
|---|---|
| `CML_API_TOKEN` | Enables bearer-token auth. |
| `CML_STORE_PATH` | Enables SQLite persistence. |
| `CML_STORE_TTL` | Controls retention TTL. |
| `CML_CORS_ORIGINS` | Restricts browser origins. |
| `CML_DISABLE_DOCS` | Hides `/docs` and `/redoc` in hardened deployments. |
| `CML_RATE_LIMIT_*` | Configures rate limits. |

## Non-goals for MVP

The hosted MVP should not claim to provide:

- full regulatory compliance,
- complete AI safety coverage,
- SIEM replacement,
- long-term evidence vault,
- policy authoring platform,
- multi-tenant enterprise governance dashboard,
- certification authority.

Those may become separate product layers after the audit contract is stable.

## Implementation path

Recommended implementation sequence:

1. Add `/v1/health` alias for `/health`.
2. Add `/v1/audit/log` alias/wrapper for `/audit`.
3. Add `/v1/audit/file` alias/wrapper for `/audit/file`.
4. Add a minimal run result store with TTL.
5. Add `GET /v1/audit/runs/{run_id}`.
6. Add tests for v1 endpoint compatibility.
7. Document deployment assumptions.

## Success criteria

The Hosted Audit API MVP is ready when:

- A user can submit JSONL and receive structured findings.
- The result preserves current CML audit codes.
- Errors are predictable and documented.
- Retention behavior is explicit.
- Authentication is required for hosted usage.
- The API does not overclaim compliance, certification, or full safety coverage.
