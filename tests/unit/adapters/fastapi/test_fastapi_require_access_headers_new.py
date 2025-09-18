import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi import HTTPException

from rbacx.adapters.fastapi import require_access
from rbacx.core.model import Action, Context, Resource, Subject


class FakeGuard:
    # expose is_allowed_sync to hit the first branch
    def is_allowed_sync(self, sub, act, res, ctx):
        return False

    def explain_sync(self, sub, act, res, ctx):
        class Expl:
            reason = "not_allowed"
            rule_id = "r1"
            policy_id = "p1"

        return Expl()


def build_env(_):
    return Subject(id="u"), Action("read"), Resource(type="doc"), Context(attrs={})


def test_fastapi_dependency_builds_reason_headers():
    dep = require_access(FakeGuard(), build_env, add_headers=True)
    with pytest.raises(HTTPException) as ei:
        dep(object())  # request object is not used by build_env
    err = ei.value
    # Headers should include our explanation fields
    assert err.headers["X-RBACX-Reason"] == "not_allowed"
    assert err.headers["X-RBACX-Rule"] == "r1"
    assert err.headers["X-RBACX-Policy"] == "p1"
