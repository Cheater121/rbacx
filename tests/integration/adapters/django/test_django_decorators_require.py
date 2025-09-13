import importlib
import sys
import types


def _purge(mod_name: str):
    """Remove from sys.modules anything that could be cached so imports are rebound from scratch."""
    for k in list(sys.modules):
        if k == mod_name or k.startswith(mod_name + "."):
            sys.modules.pop(k, None)


def _install_min_django(monkeypatch):
    """
    Minimal Django stub providing:
      - django.core.exceptions.PermissionDenied
      - django.http.HttpRequest
      - django.http.HttpResponseForbidden (403)
    This is sufficient to verify the decorator's behavior.
    """
    django = types.ModuleType("django")

    # django.core.exceptions.PermissionDenied
    core = types.ModuleType("django.core")
    exceptions = types.ModuleType("django.core.exceptions")

    class _PermissionDenied(Exception):
        pass

    exceptions.PermissionDenied = _PermissionDenied
    core.exceptions = exceptions
    django.core = core

    # django.http.{HttpRequest, HttpResponseForbidden}
    http = types.ModuleType("django.http")

    class _HttpRequest:
        def __init__(self):
            self.META = {}
            self.method = "GET"
            self.path = "/"
            self.user = types.SimpleNamespace(id="u1")

    class _HttpResponseForbidden:
        status_code = 403

        def __init__(self, content=b"", *args, **kwargs):
            self.content = content

    http.HttpRequest = _HttpRequest
    http.HttpResponseForbidden = _HttpResponseForbidden

    # register stubs in sys.modules
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.core", core)
    monkeypatch.setitem(sys.modules, "django.core.exceptions", exceptions)
    monkeypatch.setitem(sys.modules, "django.http", http)


def test_django_decorator_allows(monkeypatch):
    _purge("rbacx.adapters.django.decorators")
    _install_min_django(monkeypatch)

    import rbacx.adapters.django.decorators as deco

    importlib.reload(deco)

    class GuardOk:
        def is_allowed_sync(self, subject, action, resource, context):
            return True

    # if the module uses get_guard — patch it
    if hasattr(deco, "get_guard"):
        monkeypatch.setattr(deco, "get_guard", lambda req=None: GuardOk())

    @deco.require("read", "doc")
    def view(req=None):
        return "OK"

    assert view({}) == "OK"


def test_django_decorator_denies_audit_false_forbidden_or_exception(monkeypatch):
    """
    With strict denial (audit=False) the decorator may:
      a) raise django.core.exceptions.PermissionDenied, or
      b) return django.http.HttpResponseForbidden (status_code == 403).
    The test accepts either correct variant.
    """
    _purge("rbacx.adapters.django.decorators")
    _install_min_django(monkeypatch)

    from django.core.exceptions import PermissionDenied
    from django.http import HttpRequest, HttpResponseForbidden

    import rbacx.adapters.django.decorators as deco

    importlib.reload(deco)

    class GuardNo:
        def is_allowed_sync(self, subject, action, resource, context):
            return False

    # 1) if the decorator calls get_guard(...)
    if hasattr(deco, "get_guard"):
        monkeypatch.setattr(deco, "get_guard", lambda req=None: GuardNo())

    # 2) if the decorator takes the guard directly from the request
    req = HttpRequest()
    req.rbacx_guard = GuardNo()

    @deco.require("write", "doc", audit=False)
    def view(request):
        return "NO"

    # Accept both behaviors: either raise PermissionDenied or return a 403 response
    try:
        resp = view(req)
    except PermissionDenied:
        # OK — strict deny via exception
        return

    # If a value is returned, it must be 403
    assert isinstance(resp, HttpResponseForbidden) or getattr(resp, "status_code", None) == 403


def test_django_decorator_denies_audit_true_allows(monkeypatch):
    """
    Audit mode: even when the guard denies, the decorator allows the view to run.
    """
    _purge("rbacx.adapters.django.decorators")
    _install_min_django(monkeypatch)

    from django.http import HttpRequest

    import rbacx.adapters.django.decorators as deco

    importlib.reload(deco)

    class GuardNo:
        def is_allowed_sync(self, subject, action, resource, context):
            return False

    if hasattr(deco, "get_guard"):
        monkeypatch.setattr(deco, "get_guard", lambda req=None: GuardNo())

    req = HttpRequest()
    req.rbacx_guard = GuardNo()

    @deco.require("write", "doc", audit=True)
    def view(request):
        return "NO"

    assert view(req) == "NO"
