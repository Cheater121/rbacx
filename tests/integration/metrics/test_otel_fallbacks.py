import importlib
import sys

import pytest


def _purge(modname: str) -> None:
    # Remove a module and its submodules from sys.modules (fresh import).
    for k in list(sys.modules):
        if k == modname or k.startswith(modname + "."):
            sys.modules.pop(k, None)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_otel_no_sdk_is_noop(monkeypatch):
    """
    The adapter should work both when opentelemetry is installed and when it
    isn't. If the API package is missing, constructing OpenTelemetryMetrics()
    must raise a clear RuntimeError. If the API is importable (SDK may or may
    not be configured), construction and metric calls should be no-ops without errors.
    """
    _purge("rbacx.metrics.otel")

    try:
        import opentelemetry.metrics  # noqa: F401

        api_present = True
    except Exception:
        api_present = False

    import rbacx.metrics.otel as otel

    importlib.reload(otel)

    if not api_present:
        with pytest.raises(RuntimeError):
            otel.OpenTelemetryMetrics()
        return

    # API present: methods should be safe no-ops.
    m = otel.OpenTelemetryMetrics()
    m.inc("rbacx.decisions", labels={"path": "/", "method": "GET"})

    # Call a timing-like method if the wrapper exposes one (name varies across implementations).
    for meth in ("observe", "record"):
        fn = getattr(m, meth, None)
        if callable(fn):
            fn("rbacx.decision.time", 12.5, labels={"path": "/", "method": "GET"})
            break
    # If no public timing method is present, that's fine: only the counter is mandatory for this test.
