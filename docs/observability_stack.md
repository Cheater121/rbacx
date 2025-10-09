
# Observability (Prometheus + Grafana) via Docker Compose

A ready-to-run stack lives in `deploy/compose/metrics`:
- `app` – FastAPI demo exposing `/metrics` using `prometheus_client.generate_latest()`
- `prometheus` – scrapes `app:8000/metrics`
- `grafana` – UI at `http://localhost:3000` (admin/admin by default)

```bash
docker compose -f deploy/compose/metrics/docker-compose.yml up --build
open http://localhost:8000/docs
open http://localhost:9090
open http://localhost:3000
```

Prometheus best practices: prefer **Histograms** for latency, choose buckets thoughtfully; when changing buckets, use a new metric name and keep the old during the transition to preserve history.
