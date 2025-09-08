
from __future__ import annotations

from typing import Dict, Optional

try:
    from prometheus_client import Counter  # type: ignore
except Exception:  # pragma: no cover
    Counter = None  # type: ignore

from ..core.ports import MetricsSink


class PrometheusMetricsSink(MetricsSink):
    def __init__(self, name: str = "rbacx_decision_total", labelnames: Optional[list[str]] = None) -> None:
        if Counter is None:
            raise RuntimeError("prometheus-client is required. Install rbacx[prometheus].")
        self._counter = Counter(name, "RBACX decisions", labelnames=tuple(labelnames or ["effect","allowed","rule_id"]))  # type: ignore[arg-type]

    def inc(self, name: str, labels: Dict[str, str] | None = None) -> None:
        # ignore 'name' to keep a single series; could switch on it if multiple metrics
        (self._counter.labels(**(labels or {}))).inc()
