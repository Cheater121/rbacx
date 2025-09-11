
import pytest
rest_framework = pytest.importorskip("rest_framework")
from rest_framework.test import APIRequestFactory

from rbacx.adapters.drf import make_permission


from dataclasses import dataclass
from typing import Any

@dataclass
class Decision:
    allowed: bool
    reason: str | None = None
    rule_id: str | None = None
    policy_id: str | None = None

class FakeGuard:
    def __init__(self, allowed: bool, reason: str | None = None):
        self._allowed = allowed
        self._reason = reason
    def is_allowed_sync(self, sub, act, res, ctx) -> bool:
        return self._allowed
    def evaluate_sync(self, sub, act, res, ctx) -> Decision:
        return Decision(self._allowed, self._reason)
    def explain_sync(self, sub, act, res, ctx) -> Decision:
        return Decision(self._allowed, self._reason)


def build_env(req):
    from rbacx.core.model import Subject, Action, Resource, Context
    return (Subject(id="u"), Action("read"), Resource(type="doc"), Context(attrs={}))

def test_drf_permission_allow_and_message():
    rf = APIRequestFactory()
    req = rf.get("/x")
    Perm = make_permission(FakeGuard(True), build_env)
    p = Perm()
    assert p.has_permission(req, None) is True

    Perm2 = make_permission(FakeGuard(False, "nope"), build_env)
    p2 = Perm2()
    assert p2.has_permission(req, None) is False
    assert "nope" in p2.message
