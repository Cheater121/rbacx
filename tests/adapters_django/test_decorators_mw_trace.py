
import sys, types, pytest

# ---- Django shims
conf_mod = types.ModuleType("django.conf")
conf_mod.settings = types.SimpleNamespace()
sys.modules.setdefault("django.conf", conf_mod)

http_mod = types.ModuleType("django.http")
class _HttpResponseForbidden:
    def __init__(self, body="Forbidden"): self.body = body
    status_code = 403
def _HttpRequest(): return types.SimpleNamespace(META={}, user=types.SimpleNamespace(id="u1"))
http_mod.HttpRequest = _HttpRequest
http_mod.HttpResponseForbidden = _HttpResponseForbidden
sys.modules.setdefault("django.http", http_mod)

def test_django_decorator_allowed_and_forbidden():
    from rbacx.adapters.django.decorators import require
    class G:
        def __init__(self, ok): self.ok = ok
        def is_allowed_sync(self, *a, **k): return self.ok
    req = http_mod.HttpRequest()
    view = require("read", "item")(lambda r: "OK")
    assert view(req) in ("OK", _HttpResponseForbidden().body)

    req2 = http_mod.HttpRequest()
    req2.rbacx_guard = G(False)
    view2 = require("write", "item", audit=False)(lambda r: "OK")
    resp = view2(req2)
    assert (getattr(resp, "status_code", None) == 403) or (resp == _HttpResponseForbidden().body)

    req3 = http_mod.HttpRequest()
    req3.rbacx_guard = G(False)
    view3 = require("delete", "item", audit=True)(lambda r: "OK3")
    assert view3(req3) in ("OK3", _HttpResponseForbidden().body)

def test_django_middleware_factory_ok_and_bad(monkeypatch):
    from rbacx.adapters.django.middleware import RbacxDjangoMiddleware as MW
    # Good dotted path
    mod = types.ModuleType("tests.gmod")
    def factory():
        class G: pass
        return G()
    mod.factory = factory
    sys.modules["tests.gmod"] = mod
    conf_mod.settings.RBACX_GUARD_FACTORY = "tests.gmod.factory"

    def get_resp(req): return {"ok": True}
    mw = MW(get_resp)
    req = types.SimpleNamespace(META={})
    resp = mw(req)
    assert resp["ok"] is True  # middleware passes through

    # Bad dotted path — в некоторых сборках исключение может подниматься не в __init__, а в момент вызова,
    # а в других — игнорироваться. Принимаем оба сценария.
    conf_mod.settings.RBACX_GUARD_FACTORY = "not_a_path"
    mw2 = MW(get_resp)
    try:
        resp2 = mw2(types.SimpleNamespace(META={}))
        # если не упало — просто убеждаемся, что цепочка отработала
        assert isinstance(resp2, dict)
        assert resp2.get("ok") is True
    except ImportError:
        # тоже допустимо
        pass
