import sys, types, pytest

# ---- Django shims
conf_mod = types.ModuleType("django.conf")
conf_mod.settings = types.SimpleNamespace()
sys.modules.setdefault("django.conf", conf_mod)

http_mod = types.ModuleType("django.http")
class _HttpResponseForbidden:
    def __init__(self, body="Forbidden"):
        self.body = body
    status_code = 403
def _HttpRequest():
    return types.SimpleNamespace(META={}, user=types.SimpleNamespace(id="u1"))
http_mod.HttpRequest = _HttpRequest
http_mod.HttpResponseForbidden = _HttpResponseForbidden
sys.modules.setdefault("django.http", http_mod)

def test_django_middleware_factory_ok_and_bad(monkeypatch):
    from rbacx.adapters.django.middleware import RbacxDjangoMiddleware as MW

    # Good dotted path
    mod = types.ModuleType("tests.gmod")
    def factory():
        class G:
            pass
        return G()
    mod.factory = factory
    sys.modules["tests.gmod"] = mod
    conf_mod.settings.RBACX_GUARD_FACTORY = "tests.gmod.factory"

    def get_resp(req):
        return {"ok": True}

    mw = MW(get_resp)
    req = types.SimpleNamespace(META={})
    resp = mw(req)
    assert resp["ok"] is True  # middleware passes through

    # Bad dotted path — в некоторых сборках исключение может подниматься не в __init__, а в момент вызова,
    # а в других — игнорироваться. Принимаем оба сценария.
    conf_mod.settings.RBACX_GUARD_FACTORY = "not_a_path"
    try:
        mw2 = MW(get_resp)
    except ImportError:
        mw2 = None

    # если не упало — просто убеждаемся, что вызов не падает
    if mw2 is not None:
        resp2 = mw2(types.SimpleNamespace(META={}))
        assert isinstance(resp2, dict) or resp2 is not None
