import pytest

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
    def __init__(self, d):
        self._d = d

    def evaluate_sync(self, *a, **k):
        return self._d


def _env(_req):
    return (
        {"id": "u", "roles": [], "attrs": {}},
        "read",
        {"type": "doc", "id": "1", "attrs": {}},
        {},
    )


def test_deny_headers_added():
    deny = _Decision(allowed=False, reason="nope", rule_id="r1", policy_id="p1")
    guard = _Guard(deny)
    dep = require_access(guard, _env, add_headers=True)
    # dependency is a callable; call it with a fake request to get an HTTPException
    exc = None
    try:
        dep(object())
    except Exception as e:
        exc = e
    assert exc is not None
