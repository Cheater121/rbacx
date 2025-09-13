
# OpenTelemetry metrics

Install `rbacx[otel]` and wire `OTelMetrics`:

```python
from rbacx.core.engine import Guard

from rbacx.metrics.otel import OpenTelemetryMetrics
metrics = OpenTelemetryMetrics(meter_name="rbacx")
policy = {"rules": [{"effect": "permit"}]}
guard = Guard(policy, metrics=metrics)
```

The sink records `rbacx_decision_total` counter with attributes: `allowed`, `reason`.
See OpenTelemetry metrics API spec for creating counters and histograms.
