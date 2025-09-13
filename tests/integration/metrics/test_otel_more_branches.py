import builtins
import importlib
import sys
import types

import pytest


def _purge(mod_name: str):
    for k in list(sys.modules):
        if k == mod_name or k.startswith(mod_name + "."):
            sys.modules.pop(k, None)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_otel_import_without_sdk_graceful(monkeypatch):
    # Ensure any cached module is gone
    _purge("rbacx.metrics.otel")
    _purge("opentelemetry")
    # Make any import of opentelemetry fail
    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        if name.startswith("opentelemetry"):
            raise ImportError("No module named 'opentelemetry'")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    # Import should not propagate ImportError (module must degrade gracefully)
    mod = importlib.import_module("rbacx.metrics.otel")
    assert mod is not None


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_otel_import_with_minimal_sdk(monkeypatch):
    _purge("rbacx.metrics.otel")
    _purge("opentelemetry")

    # Build a minimal OpenTelemetry surface that rbacx.metrics.otel can interact with
    otel = types.ModuleType("opentelemetry")
    metrics = types.ModuleType("opentelemetry.metrics")

    class _Meter:
        def __init__(self):
            self.created = {"counter": [], "histogram": []}

        def create_counter(self, name, *a, **kw):
            self.created["counter"].append(name)

            class C:
                def add(self, amount: int, attributes=None):
                    pass

            return C()

        def create_histogram(self, name, *a, **kw):
            self.created["histogram"].append(name)

            class H:
                def record(self, amount: float, attributes=None):
                    pass

            return H()

    _meter = _Meter()

    def get_meter(*a, **kw):
        return _meter

    metrics.get_meter = get_meter
    monkeypatch.setitem(sys.modules, "opentelemetry", otel)
    monkeypatch.setitem(sys.modules, "opentelemetry.metrics", metrics)

    # Import and verify it binds to our minimal API without errors
    mod = importlib.import_module("rbacx.metrics.otel")
    assert mod is not None
    # Try to touch common entry points if they exist (best-effort, won't fail if absent)
    for fn_name in ("inc", "observe", "record", "emit_decision"):
        fn = getattr(mod, fn_name, None)
        if callable(fn):
            # call with minimal args; functions should no-op or use our stub
            try:
                fn("test_metric", 1, attrs={"foo": "bar"})
            except TypeError:
                # different signature - ignore
                pass
