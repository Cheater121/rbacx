import types

import pytest

import rbacx.adapters.django.middleware as mw_mod


class _DummyRequest:
    pass


def _dummy_get_response(recorder):
    def _inner(request):
        recorder["called"] = True
        return "OK"

    return _inner


@pytest.fixture(autouse=True)
def fake_settings(monkeypatch):
    """
    Replace the imported Django settings with a lightweight dummy object
    so tests don't require Django to be installed.
    """
    dummy = types.SimpleNamespace()
    monkeypatch.setattr(mw_mod, "settings", dummy, raising=True)
    return dummy


def test_init_without_factory_path_exits(fake_settings):
    """
    Covers arc `30->exit`: RBACX_GUARD_FACTORY is absent/None → the `if factory_path:` branch
    is skipped and __init__ exits without creating a guard.
    """
    # No attribute set on fake_settings → getattr(..., default=None) returns None
    called = {"called": False}
    m = mw_mod.RbacxDjangoMiddleware(_dummy_get_response(called))
    assert m._guard is None
    assert called["called"] is False  # __init__ must not call get_response


def test_call_without_guard_skips_assignment_and_calls_view(fake_settings):
    """
    Covers arc `35->37`: self._guard is None → the `if self._guard is not None:` block
    is skipped and the flow jumps to the next line (`response = ...`).
    """
    called = {"called": False}
    m = mw_mod.RbacxDjangoMiddleware(_dummy_get_response(called))
    req = _DummyRequest()

    resp = m(req)

    assert resp == "OK"
    assert called["called"] is True
    assert not hasattr(req, "rbacx_guard"), "request.rbacx_guard must not be set when guard is None"
