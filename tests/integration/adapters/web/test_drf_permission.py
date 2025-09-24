from __future__ import annotations

import sys, types, importlib
import pytest

def _ensure_drf_permissions():
    try:
        return importlib.import_module('rest_framework.permissions')
    except Exception:
        rf = types.ModuleType('rest_framework')
        perms = types.ModuleType('rest_framework.permissions')
        class BasePermission:
            message = 'forbidden'
            def has_permission(self, *a, **k):
                return True
        perms.BasePermission = BasePermission
        sys.modules['rest_framework'] = rf
        sys.modules['rest_framework.permissions'] = perms
        return perms

def _build_env(_req):
    return None, None, None, None

def test_drf_permission_allow_and_message():
    _ensure_drf_permissions()
    import types as _t
    # Import AFTER ensuring permissions to avoid BasePermission=None inside adapter
    from rbacx.adapters.drf import make_permission

    class _Guard:
        def __init__(self, allow: bool, reason: str | None = None):
            self.allow = allow
            self.reason = reason
        def evaluate_sync(self, *_a, **_k):
            return _t.SimpleNamespace(allowed=self.allow, reason=self.reason)

    RBACXPermission = make_permission(_Guard(False, reason='nope'), _build_env)
    p = RBACXPermission()
    class DummyReq: pass
    ok = p.has_permission(DummyReq(), object())
    assert ok is False
    # Depending on adapter version, DRF message may be generic or include reason
    assert p.message in ('Forbidden', 'Forbidden: nope')
