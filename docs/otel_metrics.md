
# OpenTelemetry metrics

Install `rbacx[otel]` and wire `OTelMetrics`:

```python
from rbacx.metrics.otel import OpenTelemetryMetrics
metrics = OpenTelemetryMetrics("rbacx")
guard = Guard(policy, metrics=metrics)
```

The sink records `rbacx_decision_total` counter with attributes: `allowed`, `reason`.
See OpenTelemetry metrics API spec for creating counters and histograms.
