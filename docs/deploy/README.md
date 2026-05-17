# Deploying the CML Audit API

This guide covers running the `api.server:app` FastAPI application in production.

## Quick Start: Local Docker

```bash
# Build and run locally with docker-compose
docker-compose up --build

# API is then at http://localhost:8080
curl http://localhost:8080/health
```

This sets up:
- SQLite-backed log store at `/data/cml.db` (persisted in named volume `cml-data`)
- Rate limiting enabled
- Healthcheck running every 10s

## Build the Docker Image

```bash
docker build -t causal-memory-layer:latest .
```

The `Dockerfile` uses a two-stage build:
1. **build** — installs `.[api]` extras (fastapi, uvicorn, slowapi, python-multipart) into a virtualenv
2. **runtime** — minimal image with just the venv, a non-root user (`cml`), and a healthcheck

Image size: ~250 MB.

## Configuration

All options are environment variables. Common ones:

| Variable | Default | Notes |
|----------|---------|-------|
| `PORT` | `8080` | Listening port |
| `CML_STORE_PATH` | unset | SQLite DB path (unset = in-memory store). Example: `/data/cml.db` |
| `CML_STORE_TTL` | `86400` | Record TTL in seconds (1 day default). For persistent store only. |
| `CML_API_TOKEN` | unset | Bearer token for auth. If set, all endpoints except `/health` require `Authorization: Bearer <token>` |
| `CML_CORS_ORIGINS` | `*` (no auth) / `` (with auth) | Comma-separated allowed origins. With auth enabled, defaults to deny all. |
| `CML_RATE_LIMIT_ENABLED` | `true` | Enable slowapi rate limiting |
| `CML_RATE_LIMIT_DEFAULT` | `60/minute` | Default per-key budget |
| `CML_DISABLE_DOCS` | unset | Set to `1` to hide `/docs` and `/redoc` |

### Example: with Authentication

```bash
docker run \
  -e PORT=8080 \
  -e CML_STORE_PATH=/data/cml.db \
  -e CML_API_TOKEN=my-secret-token-here \
  -e CML_CORS_ORIGINS="https://myapp.example.com" \
  -v cml-data:/data \
  -p 8080:8080 \
  causal-memory-layer:latest
```

Then use it:

```bash
curl -H "Authorization: Bearer my-secret-token-here" \
  http://localhost:8080/health
```

## Deployment Platforms

### Fly.io

1. **Install flyctl:**
   ```bash
   curl -L https://fly.io/install.sh | sh
   ```

2. **Initialize your app:**
   ```bash
   flyctl auth login
   flyctl launch --image causal-memory-layer:latest --name cml-audit-api
   # (flyctl will guide you through region selection, secrets, volumes, etc.)
   ```

3. **Set secrets (for auth + CORS):**
   ```bash
   flyctl secrets set CML_API_TOKEN=my-secret-token-here
   flyctl secrets set CML_CORS_ORIGINS="https://yourfrontend.com"
   ```

4. **Enable persistent storage (optional):**
   ```bash
   flyctl volumes create cml_data --size 10
   # Mount it in `fly.toml`: [mounts] source = "cml_data" destination = "/data"
   ```

5. **Deploy:**
   ```bash
   flyctl deploy
   ```

App will be live at `https://cml-audit-api.fly.dev` (or your chosen name).

### Render.com

1. **Push this repo to GitHub** (if not already there).

2. **Create a new Web Service on Render:**
   - Connect your GitHub repo
   - Set **Build Command:** `echo "Using Dockerfile"`
   - Set **Start Command:** leave blank (Render will use EXPOSE + CMD from Dockerfile)
   - Set **Environment Variables:**
     - `PORT=10000` (Render's default)
     - `CML_STORE_PATH=/data/cml.db`
     - `CML_API_TOKEN=...` (if auth desired)

3. **Add Disk (for persistent storage):**
   - In Service Settings → Disks, add a disk at `/data`
   - Mount path: `/data`

4. **Deploy:** Render will auto-deploy on push to main (or your chosen branch).

### Railway.app

1. **Connect your GitHub repo:**
   - New Project → GitHub repo

2. **Select the repo and add a service:**
   - Railway auto-detects the Dockerfile
   - Sets PORT to 8000 or 8080 automatically

3. **Set environment variables:**
   ```
   CML_STORE_PATH=/data/cml.db
   CML_API_TOKEN=...
   ```

4. **Add a volume (for persistent store):**
   - New → Disk
   - Mount path: `/data`

5. **Deploy:** Auto-deployed on push.

### Docker Swarm / Kubernetes

The image can run on any container orchestrator. Example k8s Deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cml-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cml-api
  template:
    metadata:
      labels:
        app: cml-api
    spec:
      containers:
      - name: cml-api
        image: causal-memory-layer:latest
        ports:
        - containerPort: 8080
        env:
        - name: PORT
          value: "8080"
        - name: CML_STORE_PATH
          value: /data/cml.db
        - name: CML_API_TOKEN
          valueFrom:
            secretKeyRef:
              name: cml-secrets
              key: api-token
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: cml-data
          mountPath: /data
      volumes:
      - name: cml-data
        persistentVolumeClaim:
          claimName: cml-data-pvc
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: cml-data-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

## API Endpoints

Once deployed, the Audit API serves:

- `GET /health` — healthcheck (no auth required)
- `POST /audit` — audit a JSONL log
- `POST /audit/file` — audit an uploaded JSONL file
- `POST /ingest` — append records to a named log store
- `GET /records/{log_name}` — list records in a log
- `GET /records/{log_name}/audit` — run audit on a stored log
- `GET /chain/{log_name}/{record_id}` — reconstruct causal chain
- `POST /ctag/decode` — decode a 16-bit CTAG value
- `GET /docs` — Swagger UI (unless `CML_DISABLE_DOCS=1`)
- `GET /redoc` — ReDoc (unless `CML_DISABLE_DOCS=1`)

See `api/server.py` docstring for detailed endpoint descriptions and examples.

## Production Checklist

- [ ] Set `CML_API_TOKEN` to a strong random string (or use your platform's secret manager)
- [ ] Set `CML_CORS_ORIGINS` to your frontend domain (not `*`)
- [ ] Enable `CML_STORE_PATH` with a persistent volume mount
- [ ] Review `CML_RATE_LIMIT_*` settings for your expected load
- [ ] Set `CML_DISABLE_DOCS=1` in production (hide swagger UI from public)
- [ ] Monitor `/health` endpoint for liveness probes
- [ ] Ensure logs are collected (via your platform's logging backend)
- [ ] Test the API with a real audit payload before going live
- [ ] Back up the SQLite DB regularly if using persistent store

## Troubleshooting

**Container exits immediately:**
- Check logs: `docker logs <container_id>`
- Ensure `PORT` env var is set and accessible
- Verify that `CML_STORE_PATH` directory exists and is writable

**`POST /audit` returns 422:**
- Check that your JSONL is valid (one record per line)
- Ensure each record has required fields: `id`, `timestamp`, `actor`, `action`, `object`, `permitted_by`
- Use `GET /docs` to test the endpoint with example payloads

**Rate limiting too strict:**
- Increase `CML_RATE_LIMIT_DEFAULT` (e.g., `"120/minute"`)
- Or disable: `CML_RATE_LIMIT_ENABLED=false` (not recommended for public APIs)

**SQLite DB locked:**
- SQLite doesn't handle concurrent writes well
- For high concurrency, consider migrating to PostgreSQL (out of scope for this guide)
- Or increase `CML_STORE_TTL` to reduce churn and run vacuums off-peak

## Next Steps

- Integrate the API with your audit pipeline
- Use the SDK (`pip install causal-memory-layer`) for local audit workflows
- Check out `docs/` for conceptual guides on CML rules and safe usage patterns
