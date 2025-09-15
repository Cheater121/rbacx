import pytest

pytest.importorskip("flask")

import pytest

from rbacx.adapters.flask import require_access


class _Decision:
    def __init__(self, allowed=False, effect="deny", reason=None, rule_id=None, policy_id=None):
        self.allowed = allowed
        self.effect = effect
        self.reason = reason
        self.rule_id = rule_id
        self.policy_id = policy_id
        self.obligations = []


class _Guard:
    def __init__(self, decision: _Decision):
        self._d = decision

    def decide(self, *args, **kwargs):
        return self._d

    # Flask adapter adds headers/reason only if guard has explain_sync
    def explain_sync(self, *args, **kwargs):
        return self._d


def _env(_req):
    return ({}, "read", {}, {})


def test_require_access_adds_headers_and_uses_jsonify(monkeypatch):
    def fake_jsonify(payload):
        return payload

    monkeypatch.setattr("rbacx.adapters.flask.jsonify", fake_jsonify, raising=True)

    decision = _Decision(allowed=False, reason="nope", rule_id="r1", policy_id="p1")
    guard = _Guard(decision)

    @require_access(guard, _env, add_headers=True)
    def handler(_):
        return "ok"

    payload, status, headers = handler(object())
    assert status == 403
    assert isinstance(payload, dict)
    assert payload.get("detail") == "forbidden"
    # With explain_sync present, reason should be propagated into JSON and headers
    assert payload.get("reason") == "nope"
    assert headers["X-RBACX-Reason"] == "nope"
    assert headers["X-RBACX-Rule"] == "r1"
    assert headers["X-RBACX-Policy"] == "p1"
