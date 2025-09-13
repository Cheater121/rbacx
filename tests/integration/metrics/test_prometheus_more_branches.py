import builtins
import importlib
import sys
import types


def _purge(mod_name: str):
    for k in list(sys.modules):
        if k == mod_name or k.startswith(mod_name + "."):
            sys.modules.pop(k, None)


def test_prom_import_without_client_graceful(monkeypatch):
    _purge("rbacx.metrics.prometheus")
    _purge("prometheus_client")
    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        if name.startswith("prometheus_client"):
            raise ImportError("No module named 'prometheus_client'")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    mod = importlib.import_module("rbacx.metrics.prometheus")
    assert mod is not None


def test_prom_import_with_minimal_client(monkeypatch):
    _purge("rbacx.metrics.prometheus")
    _purge("prometheus_client")

    prom = types.ModuleType("prometheus_client")

    class _Counter:
        def __init__(self, *a, **kw):
            self.v = 0

        def labels(self, **kw):
            return self

        def inc(self, n=1):
            self.v += n

    class _Gauge:
        def __init__(self, *a, **kw):
            self.v = 0

        def labels(self, **kw):
            return self

        def set(self, v):
            self.v = v

    prom.Counter = _Counter
    prom.Gauge = _Gauge
    monkeypatch.setitem(sys.modules, "prometheus_client", prom)

    mod = importlib.import_module("rbacx.metrics.prometheus")
    assert mod is not None
    # Probe likely helpers if present
    for name in ("inc", "set_gauge", "emit_decision"):
        fn = getattr(mod, name, None)
        if callable(fn):
            try:
                fn("x", 1, labels={"a": "b"})
            except TypeError:
                pass
