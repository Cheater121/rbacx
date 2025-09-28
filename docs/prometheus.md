# Prometheus metrics

Install the extra and wire the sink:

```bash
pip install "rbacx[metrics]"
# or: pip install prometheus-client
```

```python
from rbacx.core.engine import Guard
from rbacx.metrics.prometheus import PrometheusMetrics

metrics = PrometheusMetrics()
policy = {"rules": [{"effect": "permit"}]}
guard = Guard(policy, metrics=metrics)
```

Expose the metrics endpoint (HTTP exporter from `prometheus_client`):

```python
from prometheus_client import start_http_server
start_http_server(8000)  # scrape http://localhost:8000/
```

### What is exported

- **Counter** `rbacx_decisions_total{decision}` — increments by 1 for every decision.
  Label `decision` has values like `permit` or `deny`.

- **Histogram** `rbacx_decision_seconds` — decision evaluation duration in **seconds**.
  No labels by default.

> Notes
> - Metric names and units follow Prometheus conventions (e.g., `_total` for counters and `_seconds` for durations).
> - If `prometheus_client` is not installed, the sink safely no-ops.
