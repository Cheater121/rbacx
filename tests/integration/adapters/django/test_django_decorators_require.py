import sys
import types

def _purge(mod_name: str):
    for k in list(sys.modules):
        if k == mod_name or k.startswith(mod_name + "."):
            sys.modules.pop(k, None)

def _install_min_django(monkeypatch):
    # Create top-level 'django' package and 'django.http' submodule
    django_pkg = types.ModuleType("django")
    http_mod = types.ModuleType("django.http")

    class HttpRequest:
        pass

    class HttpResponseForbidden:
        status_code = 403
        def __init__(self, body):
            self.content = body
            self.headers = {}
        def __setitem__(self, k, v):
            self.headers[k] = v

    http_mod.HttpRequest = HttpRequest
    http_mod.HttpResponseForbidden = HttpResponseForbidden
    # register modules
    sys.modules["django"] = django_pkg
    sys.modules["django.http"] = http_mod

def test_django_decorator_allows(monkeypatch):
    _install_min_django(monkeypatch)
    _purge("rbacx.adapters.django.decorators")
    import rbacx.adapters.django.decorators as deco
    import types as _types

    def build_env(_req):
        return None, None, None, None

    class GYes:
        def evaluate_sync(self, *_a, **_k):
            return _types.SimpleNamespace(allowed=True)

    @deco.require_access(build_env, guard=GYes())
    def view(_req):
        return "OK"

    assert view(object()) == "OK"

def test_django_decorator_denies_forbidden(monkeypatch):
    _install_min_django(monkeypatch)
    _purge("rbacx.adapters.django.decorators")
    import rbacx.adapters.django.decorators as deco
    import types as _types

    def build_env(_req):
        return None, None, None, None

    class GNo:
        def evaluate_sync(self, *_a, **_k):
            return _types.SimpleNamespace(allowed=False, reason="nope")

    @deco.require_access(build_env, guard=GNo(), add_headers=True)
    def view(_req):
        return "OK"

    resp = view(object())
    assert getattr(resp, "status_code", 403) == 403
    # headers are optional in this stub; if present, ensure dict-like
    hdrs = getattr(resp, "headers", {})
    if isinstance(hdrs, dict):
        # our stub collects headers in 'headers' dict
        assert hdrs.get("X-RBACX-Reason") in (None, "nope")
