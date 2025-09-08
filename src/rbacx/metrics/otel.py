
from __future__ import annotations

from typing import Dict

try:
    from opentelemetry.metrics import get_meter  # type: ignore
except Exception:  # pragma: no cover
    get_meter = None  # type: ignore

class OpenTelemetryMetrics:
    """OpenTelemetry-based MetricsSink.

    Creates:
      - Counter: rbacx.decisions (attributes: allowed, reason)
      - Histogram: rbacx.decision.duration.ms  (optional: adapters can record)
    """
    def __init__(self, *, meter_name: str = "rbacx") -> None:
        if get_meter is None:
            raise RuntimeError("opentelemetry-api is not installed. Use `pip install rbacx[metrics]`.")
        meter = get_meter(meter_name)
        # API per OTEL metrics spec
        self.counter = meter.create_counter(name="rbacx.decisions", unit="{events}", description="RBACX decisions")  # type: ignore
        self.hist = meter.create_histogram(name="rbacx.decision.duration.ms", unit="ms", description="RBACX decision latency")  # type: ignore

    def inc(self, name: str, labels: Dict[str, str] | None = None) -> None:
        labels = labels or {}
        if name in ("rbacx_decision_total", "rbacx_decisions_total"):
            try:
                self.counter.add(1, attributes={"allowed": str(labels.get("allowed", "false")), "reason": str(labels.get("reason", ""))})  # type: ignore
            except Exception:
                pass


def observe(self, name: str, value: float, labels: Dict[str, str] | None = None) -> None:
    # If seconds-based name is used, convert to ms to match instrument
    try:
        v = float(value)
    except Exception:
        return
    try:
        if name.endswith("_seconds"):
            v = v * 1000.0
        self.hist.record(v)  # type: ignore
    except Exception:
        pass
