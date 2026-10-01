FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin evaluser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY benchmark.yaml .
COPY scenarios ./scenarios
COPY evaluators ./evaluators
COPY runners ./runners
COPY workspace ./workspace

RUN mkdir -p /app/results && chown -R evaluser:evaluser /app/results /app/workspace

USER evaluser

CMD ["python", "-m", "runners.demo_runner"]
