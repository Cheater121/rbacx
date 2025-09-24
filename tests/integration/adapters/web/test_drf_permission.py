# -*- coding: utf-8 -*-
import pytest
import types

drf = pytest.importorskip("rest_framework", reason="Optional dep: DRF not installed")

try:
    from rest_framework.permissions import BasePermission  # noqa: F401
except Exception:
    pytest.skip('DRF permissions not available', allow_module_level=True)
from rbacx.adapters.drf import make_permission

def _build_env(_req):
    return None, None, None, None

class _Guard:
    def __init__(self, allow: bool, reason: str | None = None):
        self.allow = allow
        self.reason = reason
    def evaluate_sync(self, *_a, **_k):
        return types.SimpleNamespace(allowed=self.allow, reason=self.reason)

def test_drf_permission_allow_and_message():
    RBACXPermission = make_permission(_Guard(False, reason="nope"), _build_env)
    p = RBACXPermission()
    class DummyReq: pass
    ok = p.has_permission(DummyReq(), object())
    assert ok is False
    assert p.message == "Forbidden" or p.message.startswith("Forbidden:")
