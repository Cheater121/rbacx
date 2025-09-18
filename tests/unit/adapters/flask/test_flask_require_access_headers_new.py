import pytest

flask = pytest.importorskip("flask")
from rbacx.adapters.flask import require_access
from rbacx.core.model import Action, Context, Resource, Subject


class FakeGuard:
    def is_allowed_sync(self, sub, act, res, ctx):
        return False

    def explain_sync(self, sub, act, res, ctx):
        class Expl:
            reason = "denied"
            rule_id = "rX"
            policy_id = "pY"

        return Expl()


def build_env(_):
    return Subject(id="u"), Action("write"), Resource(type="post"), Context(attrs={})


def test_flask_decorator_returns_json_tuple_with_headers():
    # Make a dummy view
    @require_access(FakeGuard(), build_env, add_headers=True)
    def view():
        return {"ok": True}

    resp = view()
    body, status, headers = resp
    assert status == 403
    assert headers["X-RBACX-Reason"] == "denied"
    assert headers["X-RBACX-Rule"] == "rX"
    assert headers["X-RBACX-Policy"] == "pY"
