import importlib
import sys

import pytest


def _force_no_starlette(monkeypatch):
    """Monkeypatch importlib.import_module so that any 'starlette.*' import raises ImportError."""
    orig_import_module = importlib.import_module

    def fake_import_module(name, package=None):
        if name.startswith("starlette."):
            raise ImportError("starlette not installed")
        return orig_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)


def _reload_starlette_adapter():
    """Reload rbacx.adapters.starlette so module-level optional imports run under current monkeypatches."""
    # Ensure a fresh import
    if "rbacx.adapters.starlette" in sys.modules:
        del sys.modules["rbacx.adapters.starlette"]
    import rbacx.adapters.starlette as mod  # noqa: F401  (import for side effects)

    return importlib.reload(sys.modules["rbacx.adapters.starlette"])


@pytest.mark.asyncio
async def test_run_in_threadpool_fallback_executes_sync_handler(monkeypatch):
    """
    Covers lines 26-29: fallback async run_in_threadpool when starlette.concurrency is unavailable.
    We also trigger lines 21-22 by making starlette.responses unavailable during import.
    """
    _force_no_starlette(monkeypatch)
    mod = _reload_starlette_adapter()

    # Guard that ALLOWS → decorator should reach the sync-handler path and use the fallback run_in_threadpool
    class Decision:
        def __init__(self, allowed):
            self.allowed = allowed

    class Guard:
        def evaluate_sync(self, sub, act, res, ctx):
            # must return an object with ".allowed"
            return Decision(True)

    def build_env(request):
        return ("s", "a", "r", {"ctx": True})

    # Sync handler to ensure the decorator goes into the run_in_threadpool branch
    def handler(request):
        return "OK"

    wrapped = mod.require_access(Guard(), build_env, add_headers=False)(handler)
    result = await wrapped(object())  # returns whatever the sync handler returns
    assert result == "OK"


def test_coerce_raises_when_jsonresponse_unavailable(monkeypatch):
    """
    Covers line 43: when both _ASGIJSONResponse and JSONResponse are None (no starlette.responses),
    _coerce_asgi_json_response must raise RuntimeError("JSONResponse is not available").
    Also exercises lines 21-22 (assignment to None on import failure).
    """
    _force_no_starlette(monkeypatch)
    mod = _reload_starlette_adapter()

    # Sanity: JSONResponse should be None in this configuration
    assert mod.JSONResponse is None

    with pytest.raises(RuntimeError) as ei:
        mod._coerce_asgi_json_response({"detail": "Forbidden"}, 403, headers=None)

    assert "JSONResponse is not available" in str(ei.value)
