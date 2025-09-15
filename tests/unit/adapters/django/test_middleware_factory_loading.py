import types

import pytest

from rbacx.adapters.django.middleware import RbacxDjangoMiddleware, _load_dotted


class DummyGuard:
    pass


def test_load_dotted_invalid():
    with pytest.raises(ImportError):
        _load_dotted("not_a_module_or_attr")  # missing module part


def test_middleware_attaches_guard(monkeypatch):
    # Prepare a dummy factory exposed via a fake module path
    module_name = "_rbacx_test_factory_mod"
    mod = types.ModuleType(module_name)

    def factory():
        return DummyGuard()

    mod.guard_factory = factory
    # install into sys.modules so import_module finds it
    import sys

    sys.modules[module_name] = mod

    # Fake Django settings with our factory path
    class Settings:
        RBACX_GUARD_FACTORY = f"{module_name}.guard_factory"

    monkeypatch.setattr("rbacx.adapters.django.middleware.settings", Settings, raising=True)

    captured = {}

    def get_response(request):
        # middleware should inject attribute before calling get_response
        captured["has_guard"] = hasattr(request, "rbacx_guard") and isinstance(
            request.rbacx_guard, DummyGuard
        )
        return "ok"

    mw = RbacxDjangoMiddleware(get_response)

    class Req: ...

    resp = mw(Req())
    assert resp == "ok" and captured["has_guard"] is True
