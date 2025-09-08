
from __future__ import annotations

from typing import Dict

try:
    from prometheus_client import REGISTRY, Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = Histogram = REGISTRY = None  # type: ignore

class PrometheusMetrics:
    """Prometheus-based MetricsSink.

    Exposes:
      - rbacx_decisions_total{allowed,reason}
      - rbacx_decision_duration_seconds (histogram)  [optional usage by adapter code]
    """
    def __init__(self, *, namespace: str = "rbacx", registry=None) -> None:
        if Counter is None or Histogram is None:
            raise RuntimeError("prometheus_client is not installed. Use `pip install rbacx[metrics]`.")
        self.decisions = Counter(f"{namespace}_decisions_total", "RBACX decisions", labelnames=["allowed","reason"], registry=registry or REGISTRY)
        self.latency = Histogram(f"{namespace}_decision_duration_seconds", "RBACX decision latency (seconds)", registry=registry or REGISTRY)

    def inc(self, name: str, labels: Dict[str, str] | None = None) -> None:
        labels = labels or {}
        if name in ("rbacx_decision_total", "rbacx_decisions_total"):
            self.decisions.labels(allowed=str(labels.get("allowed", "false")), reason=str(labels.get("reason", ""))).inc()
        # latency histogram should be observed by adapter if needed (we don't get duration here)


def observe(self, name: str, value: float, labels: Dict[str, str] | None = None) -> None:
    # Name contract: adapters call 'rbacx_decision_duration_seconds'
    if name.endswith("_seconds"):
        try:
            self.latency.observe(float(value))
        except Exception:
            pass
