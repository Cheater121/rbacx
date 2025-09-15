import importlib
import sys
import types

import pytest


def _purge(modname: str) -> None:
    # Remove a module and its submodules from sys.modules (fresh import).
    for k in list(sys.modules):
        if k == modname or k.startswith(modname + "."):
            sys.modules.pop(k, None)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_flask_require_allowed_is_allowed_branch(monkeypatch):
    """
    When the guard allows, the decorator should not modify the view result.
    We stub only `flask.jsonify` because the adapter returns JSON on deny.
    """
    _purge("rbacx.adapters.flask")

    fake_flask = types.ModuleType("flask")
    fake_flask.jsonify = lambda payload=None, **_: payload or {}
    monkeypatch.setitem(sys.modules, "flask", fake_flask)

    import rbacx.adapters.flask as fa

    importlib.reload(fa)

    class _GuardAllow:
        def is_allowed_sync(self, subject, action, resource, context):
            return True

    def _env(_req):
        return ("u1", "read", "doc", {"ip": "127.0.0.1"})

    @fa.require_access(_GuardAllow(), _env, add_headers=True)
    def view(_req=None):
        return "OK"

    assert view(object()) == "OK"


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_flask_require_denied_no_headers_and_explain_failure(monkeypatch):
    """
    When the guard denies and explain() explodes, the adapter must still
    return a 403 response. With add_headers=False, there should be no
    extra headers. Flask allows (response, status) or (response, status, headers).
    """
    _purge("rbacx.adapters.flask")

    fake_flask = types.ModuleType("flask")
    fake_flask.jsonify = lambda payload=None, **_: payload or {}
    monkeypatch.setitem(sys.modules, "flask", fake_flask)

    import rbacx.adapters.flask as fa

    importlib.reload(fa)

    class _GuardDenyExplode:
        def is_allowed_sync(self, *_a, **_k):
            return False

        def explain_sync(self, *_a, **_k):
            # Simulate unexpected error inside explain() branch.
            raise RuntimeError("boom")

    def _env(_req):
        return ("u1", "write", "doc", {"ip": "127.0.0.1"})

    @fa.require_access(_GuardDenyExplode(), _env, add_headers=False)
    def view(_req=None):
        return "NO"

    rv = view(object())

    # Flask may return (response, status) or (response, status, headers)
    assert isinstance(rv, tuple)
    assert len(rv) in (2, 3), f"unexpected Flask response tuple length: {len(rv)}"
    payload, status = rv[0], rv[1]
    assert status == 403
    assert isinstance(payload, dict)
    # No additional headers when add_headers=False
    if len(rv) == 3:
        headers = rv[2]
        assert isinstance(headers, dict)
        assert not headers
