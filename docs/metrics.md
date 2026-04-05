
# Metrics integration

RBACX can emit metrics via **Prometheus** or **OpenTelemetry**.

## Prometheus
Use `PrometheusMetrics` sink (requires `prometheus_client`). Exposes:
- `rbacx_decisions_total{allowed,reason}` — counter of decisions.
- `rbacx_decision_duration_seconds` — histogram (adapters can observe latency).
- `rbacx_batch_size` — histogram of `evaluate_batch_*` call sizes (requests per call).

## OpenTelemetry
Use `OpenTelemetryMetrics` (requires `opentelemetry-api`). Creates instruments:
- Counter `rbacx.decisions` (attributes: `allowed`, `reason`).
- Histogram `rbacx.decision.duration.ms`.
- Histogram `rbacx_batch_size` (unit: `{request}`) — `evaluate_batch_*` call sizes.

See OpenTelemetry Metrics API and Prometheus client docs for details.
