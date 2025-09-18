# Modernized Django adapter tests.
# Runs even if Django isn't installed by stubbing minimal modules.
# Comments are in English by project rule.
import sys
import types


class _Resp:
    def __init__(self, status, body=b""):
        self.status_code = status
        self.content = body
        self.headers = {}


def _ensure_fake_django(monkeypatch):
    try:
        import django  # noqa: F401

        return False  # real Django present
    except Exception:
        pass
    # Create a minimal fake 'django.conf.settings' and 'django.http' API
    django_pkg = types.ModuleType("django")
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
    # Ensure Django stub present (or real Django)
    fake = _ensure_fake_django(monkeypatch)
    from rbacx.adapters.django import middleware as mw

    # Provide dotted factory target that yields a permissive guard
    dotted_mod = types.ModuleType("tests.dotted")

    def factory():
        class _Guard:
            pass

        return _Guard()

    sys.modules["tests.dotted"] = dotted_mod
    dotted_mod.factory = factory

    # If using fake Django, set settings on the stub
    if fake:
        import django.conf  # type: ignore

        django.conf.settings.RBACX_GUARD_FACTORY = "tests.dotted.factory"
    else:
        # If real Django is present, set attribute on real settings
        from django.conf import settings as dj_settings  # type: ignore

        dj_settings.RBACX_GUARD_FACTORY = "tests.dotted.factory"

    def get_response(_request):
        return _Resp(200)

    cls = getattr(mw, "RbacxDjangoMiddleware", None) or getattr(mw, "RBACXMiddleware", None)
    assert cls is not None, "Django middleware entrypoint not found"
    req = types.SimpleNamespace(path="/", method="GET", META={}, headers={})
    resp = cls(get_response)(req)
    assert resp.status_code == 200
    # Guard should be injected for downstream use
    assert hasattr(req, "rbacx_guard")
