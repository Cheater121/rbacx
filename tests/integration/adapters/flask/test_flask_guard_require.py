import sys
import types
from importlib import reload

import pytest


class HTTPAbort(Exception):
    def __init__(self, code):
        super().__init__(f"abort({code})")
        self.code = code


def _flask_stub():
    m = types.ModuleType("flask")
    m.g = types.SimpleNamespace()

    def abort(code):
        raise HTTPAbort(code)

    m.abort = abort
    return m


def test_flask_guard_no_guard_allows(monkeypatch):
    # Isolate stubbed Flask only for this test
    monkeypatch.setitem(sys.modules, "flask", _flask_stub())
    import rbacx.adapters.flask_guard as fg

    reload(fg)

    @fg.require("read", "doc")
    def view():
        return "ok"

    assert view() == "ok"


def test_flask_guard_with_guard_permit_and_deny(monkeypatch):
    fl = _flask_stub()
    monkeypatch.setitem(sys.modules, "flask", fl)
    import rbacx.adapters.flask_guard as fg

    reload(fg)

    calls = {}

    class GuardPermit:
        def is_allowed_sync(self, subject, action, resource, context):
            calls["subject_id"] = getattr(subject, "id", None)
            calls["resource_type"] = getattr(resource, "type", None)
            return True

    fl.g.rbacx_guard = GuardPermit()
    fl.g.user = types.SimpleNamespace(id="u1")

    @fg.require("read", "doc")
    def view_ok():
        return "OK"

    assert view_ok() == "OK"
    assert calls["subject_id"] == "u1"
    assert calls["resource_type"] == "doc"

    class GuardDeny:
        def is_allowed_sync(self, *a, **k):
            return False

    fl.g.rbacx_guard = GuardDeny()

    @fg.require("write", "doc", audit=False)
    def view_forbidden():
        return "NO"

    with pytest.raises(HTTPAbort) as exc:
        view_forbidden()
    assert exc.value.code == 403

    fl.g.rbacx_guard = GuardDeny()

    @fg.require("write", "doc", audit=True)
    def view_audit():
        return "AUDIT"

    assert view_audit() == "AUDIT"


def test_flask_guard_uses_anonymous_when_no_user(monkeypatch):
    fl = _flask_stub()
    monkeypatch.setitem(sys.modules, "flask", fl)
    import rbacx.adapters.flask_guard as fg

    reload(fg)

    seen = {}

    class Guard:
        def is_allowed_sync(self, subject, *a, **k):
            seen["id"] = getattr(subject, "id", None)
            return True

    fl.g.rbacx_guard = Guard()

    @fg.require("read", "doc")
    def view():
        return "OK"

    view()
    assert seen["id"] == "anonymous"
