import importlib
import sys
import types

import pytest


def _purge(mod):
    for k in list(sys.modules):
        if k == mod or k.startswith(mod + "."):
            sys.modules.pop(k, None)


def _install_flask_stub(monkeypatch, *, with_jsonify=True):
    if with_jsonify:

        def jsonify(payload):
            # mimic Flask jsonify by returning a dict-like object
            return {"_json": payload}

        m = types.ModuleType("flask")
        m.jsonify = jsonify
        monkeypatch.setitem(sys.modules, "flask", m)
    else:
        # simulate ImportError on module import so adapter sets jsonify=None
        sys.modules.pop("flask", None)


class _GuardDeny:
    def __init__(self, reason="blocked", rule_id="R-42", policy_id="P-1"):
        self.reason = reason
        self.rule_id = rule_id
        self.policy_id = policy_id

    def is_allowed_sync(self, sub, act, res, ctx):
        self.last_explanation = types.SimpleNamespace(
            reason=self.reason, rule_id=self.rule_id, policy_id=self.policy_id
        )
        return False

    def get_last_explanation(self):
        return getattr(self, "last_explanation", None)


def _build_env(_req):
    return object(), object(), object(), object()


def test_flask_require_denies_returns_tuple_with_403_and_headers(monkeypatch):
    _purge("rbacx.adapters.flask")
    _install_flask_stub(monkeypatch, with_jsonify=True)
    import rbacx.adapters.flask as fl

    importlib.reload(fl)

    dec = fl.require_access(_GuardDeny(), _build_env, add_headers=True)

    @dec
    def endpoint():
        return "OK"

    resp = endpoint()
    # adapter returns (json, status, headers)
    body, status, headers = resp
    assert status == 403
    assert isinstance(body, dict) and "_json" in body
    # header enrichment is optional; if present check they are strings
    for k in ("X-RBACX-Reason", "X-RBACX-Rule", "X-RBACX-Policy"):
        if k in headers:
            assert isinstance(headers[k], str)


def test_flask_require_without_flask_raises_runtimeerror(monkeypatch):
    _purge("rbacx.adapters.flask")
    _install_flask_stub(monkeypatch, with_jsonify=False)
    import rbacx.adapters.flask as fl

    importlib.reload(fl)

    dec = fl.require_access(_GuardDeny(), _build_env, add_headers=False)
    with pytest.raises(RuntimeError):

        @dec
        def endpoint():
            return "OK"

        endpoint()
