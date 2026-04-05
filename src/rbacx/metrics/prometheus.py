from typing import Any

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
      - rbacx_batch_size (Histogram) — distribution of evaluate_batch_* call sizes

    Notes:
      * Counter uses the `_total` suffix and latency uses `_seconds` to follow Prometheus/OpenMetrics naming.
      * :meth:`observe` is **optional**. Guard checks for it via ``hasattr(metrics, "observe")``
        and will safely skip if missing. This adapter provides a no-op/optional implementation
        so users can see how to wire it; if the Prometheus client is not installed or the
        histogram wasn't created, the call is a no-op.
    """

    # Explicit attribute annotations for mypy
    _counter: Any | None
    _hist: Any | None
    _batch_hist: Any | None

    def __init__(self) -> None:
        # default to None so attributes are always defined
        self._counter = None
        self._hist = None
        self._batch_hist = None

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
        # Batch size histogram — number of requests per evaluate_batch_* call
        self._batch_hist = Histogram(
            "rbacx_batch_size",
            "Distribution of rbacx evaluate_batch_* call sizes (number of requests per call).",
            buckets=(1, 2, 5, 10, 25, 50, 100, 250, 500, 1000),
        )

    # -- MetricsSink ------------------------------------------------------------

    def inc(self, name: str, labels: dict[str, str] | None = None) -> None:
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
    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Record a value in the appropriate histogram.

        Routing:
          - ``"rbacx_batch_size"`` → ``rbacx_batch_size`` histogram.
          - Any other *name* → ``rbacx_decision_seconds`` latency histogram.

        Parameters
        ----------
        name: str
            Metric name used for routing (see above).
        value: float
            Value to record.  For latency use seconds; for batch size use the
            request count.
        labels: dict[str, str] | None
            Currently unused (histograms have no labels by default).
        """
        try:
            if name == "rbacx_batch_size":
                if self._batch_hist is not None:
                    self._batch_hist.observe(float(value))
            else:
                if self._hist is not None:
                    self._hist.observe(float(value))
        except Exception:  # pragma: no cover
            __import__("logging").getLogger("rbacx.metrics.prometheus").debug(
                "PrometheusMetrics.observe: failed to record histogram", exc_info=True
            )
