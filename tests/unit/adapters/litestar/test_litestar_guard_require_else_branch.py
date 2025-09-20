import importlib
import sys
import types

import pytest


def test_require_else_branch_evaluate_sync_path(monkeypatch):
    """
    Covers else-branch in rbacx.adapters.litestar_guard.require():
      decision = guard.evaluate_sync(...)
      allowed = decision.allowed
    by providing a guard WITHOUT is_allowed_sync (so the else branch is used).
    """
    # --- Minimal litestar stubs so the adapter can import ---
    litestar_pkg = types.ModuleType("litestar")

    litestar_conn = types.ModuleType("litestar.connection")

    class ASGIConnection: ...

    litestar_conn.ASGIConnection = ASGIConnection

    litestar_exc = types.ModuleType("litestar.exceptions")

    class _PermissionDeniedException(Exception): ...

    litestar_exc.PermissionDeniedException = _PermissionDeniedException

    monkeypatch.setitem(sys.modules, "litestar", litestar_pkg)
    monkeypatch.setitem(sys.modules, "litestar.connection", litestar_conn)
    monkeypatch.setitem(sys.modules, "litestar.exceptions", litestar_exc)

    # --- Import the adapter fresh (no reload; ensure entry is re-created) ---
    monkeypatch.delitem(sys.modules, "rbacx.adapters.litestar_guard", raising=False)
    ls_guard_mod = importlib.import_module("rbacx.adapters.litestar_guard")

    # Build the checker for a deny path (audit=False -> must raise)
    checker = ls_guard_mod.require("read", "doc", audit=False)

    class GuardNoIsAllowed:
        # No is_allowed_sync; force the else-branch:
        def evaluate_sync(self, *a, **k):
            # Object with .allowed = False
            return types.SimpleNamespace(allowed=False)

    with pytest.raises(_PermissionDeniedException):
        checker(ASGIConnection(), GuardNoIsAllowed())
