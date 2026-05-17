# syntax=docker/dockerfile:1.7

# ----------------------------------------------------------------------
# Build stage — install dependencies into a virtualenv so the runtime
# image only ships what we actually need.
# ----------------------------------------------------------------------
FROM python:3.11-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src

COPY pyproject.toml README.md LICENSE ./
COPY cml ./cml
COPY cli ./cli
COPY api ./api

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install ".[api]"

# ----------------------------------------------------------------------
# Runtime stage — minimal image, non-root user, healthcheck.
# ----------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8080

RUN groupadd --system --gid 1001 cml \
 && useradd  --system --uid 1001 --gid cml --home /home/cml --shell /usr/sbin/nologin cml \
 && mkdir -p /home/cml \
 && chown -R cml:cml /home/cml

COPY --from=build /opt/venv /opt/venv

WORKDIR /home/cml
USER cml

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,os,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/health',timeout=2).status==200 else 1)"

# Use a shell so $PORT is expanded at container start.
CMD ["sh", "-c", "exec uvicorn api.server:app --host 0.0.0.0 --port ${PORT}"]
