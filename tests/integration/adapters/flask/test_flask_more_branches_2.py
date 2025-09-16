import importlib
import sys
import types


def _purge(prefix: str) -> None:
    """Drop all modules that start with the given prefix from sys.modules."""
    for k in list(sys.modules):
        if k.startswith(prefix):
            sys.modules.pop(k, None)


def _install_min_flask(monkeypatch):
    """
    Provide a tiny 'flask' module with jsonify() and make_response().
    This is enough for the adapter to construct a response.
    Flask allows returning a tuple (body, status, headers).
    """
    fake = types.ModuleType("flask")

    def jsonify(obj):
        return {"json": obj}

    def make_response(body, status=200, headers=None):
        return body, status, (headers or {})

    fake.jsonify = jsonify
    fake.make_response = make_response

    monkeypatch.setitem(sys.modules, "flask", fake)


def test_flask_require_allowed_is_allowed_branch(monkeypatch):
    """
    When guard allows via 'is_allowed' (not the sync variant), decorator should call the view.
    """
    _install_min_flask(monkeypatch)
    _purge("rbacx.adapters.flask")

    import rbacx.adapters.flask as fl

    importlib.reload(fl)

    class _GuardAllow:
        def is_allowed(self, subject, action, resource, context):
            return True

    def _build_env(_req):
        return ("u", "read", "doc", {})

    called = {"view": False}

    @fl.require_access(_GuardAllow(), _build_env, add_headers=False)
    def view(*_):
        called["view"] = True
        return "OK"

    # Call without real Flask request; adapter should not require it for allow path.
    res = view(object())
    assert res == "OK"
    assert called["view"] is True


def test_flask_require_denied_no_headers_and_explain_failure(monkeypatch):
    """
    On deny with add_headers=False and failing explain(), the adapter should still
    return a 403 response without any extra headers (content of 'reason' may be None).
    """
    _install_min_flask(monkeypatch)
    _purge("rbacx.adapters.flask")

    import rbacx.adapters.flask as fl

    importlib.reload(fl)

    class _GuardDeny:
        def is_allowed(self, subject, action, resource, context):
            return False

        def explain(self, subject, action, resource, context):
            raise RuntimeError("boom")

    def _build_env(_req):
        return ("u", "write", "doc", {})

    @fl.require_access(_GuardDeny(), _build_env, add_headers=False)
    def view(*_):
        return "UNREACHABLE"

    body, status, headers = view(object())
    assert status == 403
    assert isinstance(body, dict) or isinstance(body, tuple) or isinstance(body, list)
    assert headers == {}
