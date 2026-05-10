# 🚀 Hosted Audit API: cURL Examples

This document provides practical `curl` examples to interact with the local CML FastAPI server. For the architectural contract and future `/v1/*` hosted shapes, please refer to the [Hosted Audit API MVP](./HOSTED_AUDIT_API_MVP.md) document.

> **Note:** These examples are intended for local testing and development purposes to understand the expected request and response shapes. They do not represent claims about production deployment or hosted availability.

## 🏁 Starting the Local Server
Before running the commands, start the local server:
```bash
uvicorn api.server:app --reload --port 8080
```

## 📡 Endpoints & Examples

### 1. Health Check (`GET /health`)
Verify that the API is up and running.
```bash
curl http://localhost:8080/health
```

### 2. Submit Inline Audit Log (`POST /audit`)
Submit a single JSONL log inline for validation.
```bash
curl -X POST http://localhost:8080/audit \
  -H "Content-Type: application/json" \
  -d '{
    "log": "{\"id\":\"r1\",\"timestamp\":1715340000,\"actor\":{\"pid\":1,\"uid\":1},\"action\":\"exec\",\"object\":\"/bin/sh\",\"permitted_by\":\"root_event:init\"}",
    "format": "json"
  }'
```

### 3. Submit Audit Log File (`POST /audit/file`)
Upload a physical `.jsonl` file containing multiple causal records.
```bash
curl -X POST http://localhost:8080/audit/file \
  -F "file=@my_causal_log.jsonl"
```

### 4. Decode CTAG (`POST /ctag/decode`)
Decode a causal tag from hexadecimal to its JSON representation.
```bash
curl -X POST http://localhost:8080/ctag/decode \
  -H "Content-Type: application/json" \
  -d '{"ctag":"0x1234"}'
```

### 5. Authenticated Request Example
When the Hosted API is active, endpoints will require a bearer token. Use the `CML_API_TOKEN` environment variable.
When the Hosted API is active, endpoints will require a bearer token. Use the `CML_API_TOKEN` environment variable.
```bash
curl -X POST http://localhost:8080/audit \
  -H "Authorization: Bearer $CML_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "log": "{\"id\":\"r2\",\"timestamp\":1715340001,\"actor\":{\"pid\":2,\"uid\":1000},\"action\":\"login\",\"object\":\"/system\",\"permitted_by\":\"root_event:init\"}",
    "format": "json"
  }'
```

## 📦 Expected Response Shapes

### ✅ Success Response Example
```json
{
  "run_id": "run_01HZXAMPLE",
  "status": "completed",
  "summary": {
    "record_count": 1,
    "finding_count": 0,
    "passed": true
  },
  "findings": [],
  "artifacts": {
    "json": "/v1/audit/runs/run_01HZXAMPLE",
    "markdown": null
  }
}
```

### ❌ Common Error Response Example (Validation/Causal Failure)
```json
{
  "detail": [
    {
      "loc": ["body", "log"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```
### ⚠️ Causal Finding (Example)
If the log is valid JSONL but fails causal rules:
```json
{
  "run_id": "run_01HZXAMPLE",
  "status": "completed",
  "summary": {
    "record_count": 12,
    "finding_count": 1,
    "passed": false
  },
  "findings": [
    {
      "code": "CML-AUDIT-R1-MISSING_PARENT",
      "severity": "high",
      "record_id": "r7",
      "message": "Record references a missing parent cause."
    }
  ]
}
```
