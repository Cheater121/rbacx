# Modernized Django adapter tests with robust stubbing.
# If a partial 'django' package exists without 'conf'/'http', we still install a stub.
# The stub marks 'django' as a package and exposes 'conf' and 'http' as attributes to
# allow both 'import django.conf' and attribute access 'django.conf'.
# Comments in English by project rule.
import sys
import types


class _Resp:
    def __init__(self, status, body=b""):
        self.status_code = status
        self.content = body
        self.headers = {}


def _ensure_fake_django(monkeypatch):
    need_stub = False
    try:
        import django  # noqa: F401

        # If django exists but lacks expected submodules, we will stub them.
        try:
            import django.conf  # type: ignore  # noqa: F401
            import django.http  # type: ignore  # noqa: F401
        except Exception:
            need_stub = True
    except Exception:
        need_stub = True

    if not need_stub:
        return False  # Real and usable Django present

    # Create a minimal fake 'django' package with 'conf' and 'http' submodules
    django_pkg = types.ModuleType("django")
    django_pkg.__path__ = []  # mark as package so 'import django.conf' works
    conf_mod = types.ModuleType("django.conf")
    http_mod = types.ModuleType("django.http")

    class HttpResponseForbidden:
        def __init__(self, body):
            self.status_code = 403
            self.content = (body or "").encode("utf-8")
            self.headers = {}

    http_mod.HttpResponseForbidden = HttpResponseForbidden
    http_mod.HttpRequest = object  # only for type hints

    settings = types.SimpleNamespace(RBACX_GUARD_FACTORY=None)
    conf_mod.settings = settings

    # Link submodules as attributes on package for attribute access 'django.conf'
    django_pkg.conf = conf_mod
    django_pkg.http = http_mod

    # Register/override modules in sys.modules
    monkeypatch.setitem(sys.modules, "django", django_pkg)
    monkeypatch.setitem(sys.modules, "django.conf", conf_mod)
    monkeypatch.setitem(sys.modules, "django.http", http_mod)
    return True  # fake installed


def test_decorator_forbidden_and_audit_modes(monkeypatch):
    _ensure_fake_django(monkeypatch)
    from rbacx.adapters.django.decorators import require

    # Guard that denies with explain
    class _Guard:
        def is_allowed_sync(self, *_a, **_k) -> bool:
            return False

    def view(_request):  # returns 200 when not blocked
        return _Resp(200, b"ok")

    wrapped = require("read", "doc", audit=False)(view)
    req = types.SimpleNamespace(path="/x", method="GET", META={}, headers={}, rbacx_guard=_Guard())
    resp = wrapped(req)
    assert getattr(resp, "status_code", None) == 403

    wrapped_audit = require("read", "doc", audit=True)(view)
    resp2 = wrapped_audit(req)
    assert resp2.status_code == 200


def test_middleware_factory_loading_success(monkeypatch):
    _ensure_fake_django(monkeypatch)
    from rbacx.adapters.django import middleware as mw

    # Provide dotted factory target that yields a permissive guard
    dotted_mod = types.ModuleType("tests.dotted")

    def factory():
        class _Guard:
            pass

        return _Guard()

    sys.modules["tests.dotted"] = dotted_mod
    dotted_mod.factory = factory

    # Set the value on the SAME settings object that middleware imported.
    # This avoids leakage from other tests and works even with partial/real Django.
    mw.settings.RBACX_GUARD_FACTORY = "tests.dotted.factory"

    def get_response(_request):
        return _Resp(200)

    cls = getattr(mw, "RbacxDjangoMiddleware", None) or getattr(mw, "RBACXMiddleware", None)
    assert cls is not None, "Django middleware entrypoint not found"
    req = types.SimpleNamespace(path="/", method="GET", META={}, headers={})
    resp = cls(get_response)(req)
    assert resp.status_code == 200
    assert hasattr(req, "rbacx_guard")
