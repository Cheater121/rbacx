from __future__ import annotations

from typing import Any, Dict, Optional

from rbacx.core.ports import MetricsSink

try:
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore


class PrometheusMetrics(MetricsSink):
    """Prometheus-based MetricsSink with unified metric names.

    Exposes:
      - rbacx_decisions_total{decision="allow|deny|..."}
      - rbacx_decision_seconds (Histogram)  — declared for symmetry; not used here.
    """

    # Explicit attribute annotations for mypy
    _counter: Optional[Any]
    _hist: Optional[Any]

    def __init__(self) -> None:
        # default to None so attributes are always defined
        self._counter = None
        self._hist = None

        # create instruments only if the client is available
        if Counter is None or Histogram is None:  # pragma: no cover
            return

        # unified instruments
        self._counter = Counter(
            "rbacx_decisions_total",
            "Total RBACX decisions by effect.",
            labelnames=("decision",),
        )
        self._hist = Histogram(
            "rbacx_decision_seconds",
            "RBACX decision evaluation duration in seconds.",
        )

    # -- MetricsSink ------------------------------------------------------------

    def inc(self, name: str, labels: Dict[str, str] | None = None) -> None:
        """Increment the unified counter.

        The *name* parameter is accepted for backward compatibility but ignored;
        this sink always increments `rbacx_decisions_total`.
        """
        if self._counter is None:  # pragma: no cover
            return
        decision = (labels or {}).get("decision", "unknown")
        try:
            # prometheus_client's Counter.labels returns a Child; we keep type loose (Any)
            self._counter.labels(decision=decision).inc()  # type: ignore[call-arg]
        except Exception:  # pragma: no cover
            # never raise from metrics path
            pass
