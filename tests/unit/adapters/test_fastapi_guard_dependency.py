import importlib

import pytest


def test_fastapi_guard_dependency_builds_context(monkeypatch):
    """
    The dependency should build Context with attributes from 'context_getter'.
    The library may call Context either as Context(attrs=...) or Context(**attrs),
    so our stub accepts both forms to keep the test robust to internal changes.
    """
    try:
        import rbacx.adapters.fastapi_guard as fg
    except ImportError:
        pytest.skip("Module deleted")

    importlib.reload(fg)

    captured = {}

    class _Ctx(dict):
        def __init__(self, *args, **kwargs):
            # Accept Context(attrs=...) OR Context(**attrs)
            if args and isinstance(args[0], dict) and not kwargs:
                data = dict(args[0])
            elif "attrs" in kwargs and isinstance(kwargs["attrs"], dict):
                data = dict(kwargs["attrs"])
            else:
                data = dict(kwargs)
            super().__init__(**data)
            captured.clear()
            captured.update(data)

    monkeypatch.setattr(fg, "Context", _Ctx, raising=True)

    class _Guard:
        pass

    def _context_getter(_request):
        return {"path": "/", "method": "GET"}

    dep = fg.make_guard_dependency(_Guard(), context_getter=_context_getter)

    # FastAPI Request is type-hinted only; any object will do for the dependency call here.
    assert dep(object()) is None
    assert captured == {"path": "/", "method": "GET"}
