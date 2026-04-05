from typing import Any

from rbacx.core.ports import MetricsSink

try:
    from opentelemetry.metrics import get_meter  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    get_meter = None  # type: ignore


class OpenTelemetryMetrics(MetricsSink):
    """OpenTelemetry-based MetricsSink with unified metric names.

    Creates:
      - Counter: rbacx_decisions_total (labels: decision)
      - Histogram: rbacx_decision_seconds (unit: s)
      - Histogram: rbacx_batch_size (unit: {request}) — evaluate_batch_* call sizes

    Notes:
      * OTEL recommends carrying the **unit** in metadata; we also keep `_seconds` in the name
        for Prometheus/OpenMetrics interoperability.
      * :meth:`observe` is **optional**; if no SDK is configured or histogram creation fails,
        the method will no-op safely.
    """

    # Explicit attribute annotations for mypy
    _counter: Any | None
    _hist: Any | None
    _batch_hist: Any | None

    def __init__(self) -> None:
        # Ensure attributes always exist
        self._counter = None
        self._hist = None
        self._batch_hist = None

        if get_meter is None:  # pragma: no cover
            return

        meter = get_meter("rbacx.metrics")
        # Counter
        try:
            self._counter = meter.create_counter(
                name="rbacx_decisions_total",
                description="Total RBACX decisions by effect.",
            )
        except Exception:  # pragma: no cover
            self._counter = None

        # Histogram (declared for exporters/adapters that may use it)
        try:
            # Some SDKs use create_histogram, others use meter.create_histogram
            create_hist = getattr(meter, "create_histogram", None)
            if create_hist is not None:
                self._hist = create_hist(
                    name="rbacx_decision_seconds",
                    description="RBACX decision evaluation duration in seconds.",
                    unit="s",
                )
            else:  # pragma: no cover
                self._hist = None
        except Exception:  # pragma: no cover
            self._hist = None

        # Batch size histogram
        try:
            create_hist = getattr(meter, "create_histogram", None)
            if create_hist is not None:
                self._batch_hist = create_hist(
                    name="rbacx_batch_size",
                    description="Distribution of evaluate_batch_* call sizes (requests per call).",
                    unit="{request}",
                )
            else:  # pragma: no cover
                self._batch_hist = None
        except Exception:  # pragma: no cover
            self._batch_hist = None

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
            # OpenTelemetry Counter expects amount (int/float) and attributes (labels)
            self._counter.add(1, {"decision": decision})
        except Exception:  # pragma: no cover
            __import__("logging").getLogger("rbacx.metrics.otel").debug(
                "OpenTelemetryMetrics.inc: failed to add to counter", exc_info=True
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
            Metric name used for routing.
        value: float
            Value to record.
        labels: dict[str, str] | None
            OTEL Histogram accepts attributes; passed through if present.
        """
        try:
            if name == "rbacx_batch_size":
                if self._batch_hist is not None:
                    self._batch_hist.record(float(value), attributes=dict(labels or {}))
            else:
                if self._hist is not None:
                    self._hist.record(float(value), attributes=dict(labels or {}))
        except Exception:  # pragma: no cover
            __import__("logging").getLogger("rbacx.metrics.otel").debug(
                "OpenTelemetryMetrics.observe: failed to record histogram", exc_info=True
            )
