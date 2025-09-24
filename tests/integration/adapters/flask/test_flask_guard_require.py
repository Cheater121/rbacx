import types
import pytest

flask = pytest.importorskip("flask", reason="Optional dep: Flask not installed")
from flask import Flask
from rbacx.adapters.flask import require_access

def _build_env(_req):
    return None, None, None, None

def _with_ctx(call):
    app = Flask(__name__)
    with app.app_context():
        return call()

def test_flask_guard_allows():
    class AllowGuard:
        def evaluate_sync(self, *_a, **_k):
            return types.SimpleNamespace(allowed=True)

    @require_access(AllowGuard(), _build_env)
    def view():
        return "OK"

    assert _with_ctx(view) == "OK"

def test_flask_guard_denies_with_headers():
    class DenyGuard:
        def evaluate_sync(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason="nope", rule_id="r1", policy_id="p1")

    @require_access(DenyGuard(), _build_env, add_headers=True)
    def view():
        return "OK"

    resp = _with_ctx(view)
    body, status, headers = resp
    assert status == 403
    assert headers.get("X-RBACX-Reason") == "nope"
    assert headers.get("X-RBACX-Rule") == "r1"
    assert headers.get("X-RBACX-Policy") == "p1"
