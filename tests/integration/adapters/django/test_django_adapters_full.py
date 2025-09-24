import types
import pytest

django = pytest.importorskip("django", reason="Optional dep: Django not installed")

from rbacx.adapters.django.decorators import require_access

class _G:
    def __init__(self, allow: bool, reason: str | None = None):
        self.allow = allow
        self.reason = reason
    def evaluate_sync(self, *_a, **_k):
        return types.SimpleNamespace(allowed=self.allow, reason=self.reason)

def _build_env(request):
    return None, None, None, None

def test_decorator_forbidden_and_audit_modes():
    @require_access(_build_env, guard=_G(False))
    def view_forbidden(_req):
        return "OK"
    resp = view_forbidden(object())
    assert getattr(resp, "status_code", 403) == 403

    @require_access(_build_env, guard=_G(False), audit=True)
    def view_audit(_req):
        return "OK"
    assert view_audit(object()) == "OK"
