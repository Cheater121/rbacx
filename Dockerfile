
# Builder: install deps in a venv
FROM python:3.11-slim AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -U pip
COPY . /app
RUN /opt/venv/bin/pip install --no-cache-dir -e .[examples]

# Runtime: copy venv, create non-root user, install curl for healthchecks
FROM python:3.11-slim AS runtime
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /opt/venv /opt/venv
COPY . /app
# create unprivileged user
RUN useradd -m rbacx && chown -R rbacx:rbacx /app
USER rbacx
EXPOSE 8000 8001 8002 8003
CMD ["bash", "-lc", "uvicorn examples.fastapi_demo.app:app --host 0.0.0.0 --port 8000 --log-config examples/logging/uvicorn_logging_json.yml"]
