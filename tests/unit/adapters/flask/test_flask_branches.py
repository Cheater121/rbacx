import types
import pytest

flask = pytest.importorskip("flask", reason="Optional dep: Flask not installed")
from flask import Flask
import rbacx.adapters.flask as fl_mod

def _build_env(_req):
    return None, None, None, None

def _with_ctx(call):
    app = Flask(__name__)
    with app.app_context():
        return call()

def test_flask_headers_reason_rule_policy_falsy_and_jsonify_present():
    class GuardDenied:
        def evaluate_sync(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason=None, rule_id=None, policy_id=None)

    dep = fl_mod.require_access(GuardDenied(), _build_env, add_headers=True)

    @dep
    def view(*args, **kwargs):
        return "OK"

    res = _with_ctx(view)
    assert isinstance(res, tuple) and len(res) == 3
    payload, status, headers = res
    assert status == 403
    assert headers == {}
