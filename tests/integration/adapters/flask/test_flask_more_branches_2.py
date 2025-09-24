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

def test_flask_allowed_pass_through():
    class _G:
        def evaluate_sync(self, *_a, **_k):
            return types.SimpleNamespace(allowed=True)
    @require_access(_G(), _build_env)
    def view():
        return "OK"
    assert _with_ctx(view) == "OK"

def test_flask_denied_min_headers():
    class _G:
        def evaluate_sync(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False)
    @require_access(_G(), _build_env)
    def view():
        return "OK"
    resp = _with_ctx(view)
    assert isinstance(resp, tuple) and resp[1] == 403

def test_flask_headers_present_when_add_headers_true():
    class _G:
        def evaluate_sync(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason="R", rule_id="RID", policy_id="PID")
    @require_access(_G(), _build_env, add_headers=True)
    def view():
        return "OK"
    resp = _with_ctx(view)
    assert isinstance(resp, tuple) and resp[1] == 403
    headers = resp[2]
    assert headers.get("X-RBACX-Reason") == "R"
    assert headers.get("X-RBACX-Rule") == "RID"
    assert headers.get("X-RBACX-Policy") == "PID"
