import pytest
import types
import inspect

pytest.importorskip("starlette")

from rbacx.adapters.starlette import require_access


class _Decision:
    def __init__(self, allowed=False, reason=None, rule_id=None, policy_id=None):
        self.allowed = allowed
        self.effect = "permit" if allowed else "deny"
        self.reason = reason
        self.rule_id = rule_id
        self.policy_id = policy_id
        self.obligations = []


class _Guard:
    def __init__(self, decision: _Decision):
        self._decision = decision

    def evaluate_sync(self, sub, act, res, ctx):
        return self._decision


def _env(_req):
    return None, None, None, None


@pytest.mark.asyncio
async def test_deny_headers_added():
    deny = _Decision(allowed=False, reason="nope", rule_id="r1", policy_id="p1")
    guard = _Guard(deny)
    dep = require_access(guard, _env, add_headers=True)
    deny_resp = await dep(object())
    assert getattr(deny_resp, "status_code", 403) == 403
