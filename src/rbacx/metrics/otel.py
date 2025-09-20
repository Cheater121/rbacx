from __future__ import annotations

from typing import Any, Dict, Optional

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

    Notes:
      * OTEL recommends carrying the **unit** in metadata; we also keep `_seconds` in the name
        for Prometheus/OpenMetrics interoperability.
      * :meth:`observe` is **optional**; if no SDK is configured or histogram creation fails,
        the method will no-op safely.
    """

    # Explicit attribute annotations for mypy
    _counter: Optional[Any]
    _hist: Optional[Any]

    def __init__(self) -> None:
        # Ensure attributes always exist
        self._counter = None
        self._hist = None

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
            # OpenTelemetry Counter expects amount (int/float) and attributes (labels)
            self._counter.add(1, {"decision": decision})
        except Exception:  # pragma: no cover
            __import__("logging").getLogger("rbacx.metrics.otel").debug(
                "OpenTelemetryMetrics.inc: failed to add to counter", exc_info=True
            )

    # ----------------------------- Optional extension --------------------------
    def observe(self, name: str, value: float, labels: Dict[str, str] | None = None) -> None:
        """Optionally record a latency distribution **in seconds**.

        This is a **carcass method** so users can see how to implement it. Guard will call it
        only if present (checked via ``hasattr``). If no OTEL SDK/pipeline is configured or
        the histogram wasn't created, this method safely no-ops.

        Parameters
        ----------
        name: str
            Metric name. Accepted for compatibility and future extensions; ignored here.
        value: float
            Duration **in seconds** (as exposed by Guard).
        labels: Dict[str, str] | None
            OTEL Histogram accepts attributes; we pass them through if present.
        """
        if self._hist is None:
            return
        try:
            # Histogram.record(value, attributes=labels) is the conventional API.
            self._hist.record(float(value), attributes=dict(labels or {}))
        except Exception:  # pragma: no cover
            __import__("logging").getLogger("rbacx.metrics.otel").debug(
                "OpenTelemetryMetrics.observe: failed to record histogram", exc_info=True
            )
