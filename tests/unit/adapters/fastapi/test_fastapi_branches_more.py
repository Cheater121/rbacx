import types

import pytest

import rbacx.adapters.fastapi as fa_mod


class DummyHTTPException(Exception):
    def __init__(self, status_code: int, detail=None, headers=None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.headers = headers or {}


def _build_env(_req):
    # Minimal stand-ins; dependency only passes them through.
    Subject = types.SimpleNamespace
    Action = types.SimpleNamespace
    Resource = types.SimpleNamespace
    Context = types.SimpleNamespace
    return (
        Subject(id="u"),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )


def test_no_is_allowed_attribute_triggers_raise_on_false_branch(monkeypatch):
    """
    Cover arc 25->27: guard has neither `is_allowed_sync` nor `is_allowed`,
    so the `elif hasattr(guard, "is_allowed")` condition is False and flow
    jumps directly to `if allowed:` (with allowed=False), leading to a 403.
    """
    # Provide a dummy HTTPException so FastAPI is not required
    monkeypatch.setattr(fa_mod, "HTTPException", DummyHTTPException, raising=True)

    class GuardNoMethods:
        # Intentionally no is_allowed_sync / is_allowed
        pass

    dep = fa_mod.require_access(GuardNoMethods(), _build_env, add_headers=False)

    with pytest.raises(DummyHTTPException) as ei:
        dep(object())

    exc = ei.value
    assert exc.status_code == 403
    assert exc.headers == {}
    assert exc.detail == {"reason": None}
