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

class FakeGuard:
    def evaluate_sync(self, *_a, **_k):
        return types.SimpleNamespace(allowed=False, reason="denied", rule_id="rX", policy_id="pY")

def test_flask_decorator_returns_json_tuple_with_headers():
    @require_access(FakeGuard(), _build_env, add_headers=True)
    def view():
        return {"ok": True}

    res = _with_ctx(view)
    body, status, headers = res
    assert status == 403
    assert headers["X-RBACX-Reason"] == "denied"
    assert headers["X-RBACX-Rule"] == "rX"
    assert headers["X-RBACX-Policy"] == "pY"
