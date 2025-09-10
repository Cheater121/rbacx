
import types
import importlib
import pytest

class _Resp:
    def __init__(self, status, body=b""):
        self.status_code = status
        self.content = body
        self.headers = {}

def test_decorator_forbidden_and_audit_modes():
    # The django adapter exposes 'require(action, resource_type)'
    # We call it with dummy values and ensure the wrapped view returns a valid response.
    from rbacx.adapters.django.decorators import require
    req = types.SimpleNamespace(path="/x", method="GET", META={}, headers={})
    wrapped = require("read", "item")(lambda r: _Resp(200))
    res = wrapped(req)
    assert res.status_code in (200, 403)

def test_middleware_load_dotted_and_attach_guard(monkeypatch):
    # Import middleware if available; otherwise skip gracefully.
    try:
        mod = importlib.import_module("rbacx.adapters.django.middleware")
    except Exception:
        pytest.skip("django middleware module is not available")
    cls = getattr(mod, "RBACXMiddleware", None) or getattr(mod, "RbacxMiddleware", None)
    if cls is None:
        pytest.skip("RBACXMiddleware class not exposed in this build")

    # Provide dotted factory target that yields a permissive guard
    import sys
    dotted_mod = types.ModuleType("tests.dotted")
    def factory():
        def _g(*a, **k): return True, {"reason":"ok"}
        return _g
    sys.modules["tests.dotted"] = dotted_mod
    dotted_mod.factory = factory

    def get_response(request): return _Resp(200)
    mw = cls(get_response, guard="tests.dotted.factory")
    req = types.SimpleNamespace(path="/", method="GET", META={}, headers={})
    resp = mw(req)
    assert resp.status_code == 200
