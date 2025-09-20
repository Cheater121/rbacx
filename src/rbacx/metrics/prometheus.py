from __future__ import annotations

from typing import Any, Dict, Optional

from rbacx.core.ports import MetricsSink

try:
    from prometheus_client import Counter, Histogram  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore


class PrometheusMetrics(MetricsSink):
    """Prometheus-based MetricsSink with unified metric names.

    Exposes:
      - rbacx_decisions_total{decision="allow|deny|..."}
      - rbacx_decision_seconds (Histogram) — optional latency distribution

    Notes:
      * Counter uses the `_total` suffix and latency uses `_seconds` to follow Prometheus/OpenMetrics naming.
      * :meth:`observe` is **optional**. Guard checks for it via ``hasattr(metrics, "observe")``
        and will safely skip if missing. This adapter provides a no-op/optional implementation
        so users can see how to wire it; if the Prometheus client is not installed or the
        histogram wasn't created, the call is a no-op.
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
        # Latency histogram in **seconds** (no labels by default)
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
            self._counter.labels(decision=decision).inc()
        except Exception:  # pragma: no cover
            __import__("logging").getLogger("rbacx.metrics.prometheus").debug(
                "PrometheusMetrics.inc: failed to increment counter", exc_info=True
            )

    # ----------------------------- Optional extension --------------------------
    def observe(self, name: str, value: float, labels: Dict[str, str] | None = None) -> None:
        """Optionally record a latency distribution **in seconds**.

        This is a **carcass method** so users can see how to implement it. Guard will call it
        only if present (checked via ``hasattr``). If Prometheus is unavailable or the histogram
        wasn't created, this method safely no-ops.

        Parameters
        ----------
        name: str
            Metric name. Accepted for compatibility and future extensions; ignored here.
        value: float
            Duration **in seconds** (as exposed by Guard).
        labels: Dict[str, str] | None
            Currently unused (histogram has no labels by default).
        """
        if self._hist is None:
            return
        try:
            self._hist.observe(float(value))  # seconds
        except Exception:  # pragma: no cover
            __import__("logging").getLogger("rbacx.metrics.prometheus").debug(
                "PrometheusMetrics.observe: failed to record histogram", exc_info=True
            )
