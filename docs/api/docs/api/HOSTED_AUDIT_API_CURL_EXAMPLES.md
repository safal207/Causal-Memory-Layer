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
  -d '{"log":"{\"id\":\"r1\",\"kind\":\"root\",\"actor\":\"system\",\"action\":\"init\"}\n","format":"json"}'
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
```bash
curl -X POST http://localhost:8080/audit \
  -H "Authorization: Bearer $CML_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"log":"{\"id\":\"r2\",\"kind\":\"root\",\"actor\":\"admin\",\"action\":\"login\"}\n","format":"json"}'
```

## 📦 Expected Response Shapes

### ✅ Success Response Example
```json
{
  "status": "success",
  "message": "Validation passed",
  "data": {
    "valid": true
  }
}
```

### ❌ Common Error Response Example (Validation/Causal Failure)
```json
{
  "status": "error",
  "error_code": "CML-AUDIT-R1-MISSING_PARENT",
  "message": "The log is functionally correct but causally invalid: missing parent reference."
}
```