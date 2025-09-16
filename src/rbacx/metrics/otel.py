from __future__ import annotations

from typing import Any, Dict, Optional

from rbacx.core.ports import MetricsSink

try:
    from opentelemetry.metrics import get_meter  # type: ignore
except Exception:  # pragma: no cover
    get_meter = None  # type: ignore


class OpenTelemetryMetrics(MetricsSink):
    """OpenTelemetry-based MetricsSink with unified metric names.

    Creates:
      - Counter: rbacx_decisions_total (labels: decision)
      - Histogram: rbacx_decision_seconds (unit: s)
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
            self._counter = meter.create_counter(  # type: ignore[attr-defined]
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
                self._hist = create_hist(  # type: ignore[misc]
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
            self._counter.add(1, {"decision": decision})  # type: ignore[attr-defined]
        except Exception:  # pragma: no cover
            pass
