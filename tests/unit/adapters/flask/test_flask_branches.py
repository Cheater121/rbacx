# tests/unit/adapters/test_flask_branches.py
import types

import rbacx.adapters.flask as fl_mod


def _build_env(_req):
    # Minimal stand-ins; the decorator only forwards them to guard methods.
    Subject = types.SimpleNamespace
    Action = types.SimpleNamespace
    Resource = types.SimpleNamespace
    Context = types.SimpleNamespace
    return (
        Subject(id="u"),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )


def test_flask_headers_reason_rule_policy_falsy_and_jsonify_present(monkeypatch):
    """
    Covers arcs in rbacx.adapters.flask.require_access:
      39->41: reason is falsy → skip setting X-RBACX-Reason
      41->43: rule_id is falsy → skip setting X-RBACX-Rule
      43->46: policy_id is falsy → skip setting X-RBACX-Policy and proceed to jsonify
    """

    # Provide a jsonify stub so we don't depend on Flask being installed.
    def _jsonify(obj):
        return obj

    monkeypatch.setattr(fl_mod, "jsonify", _jsonify, raising=True)

    class _Expl:
        reason = None
        rule_id = None
        policy_id = None

    class GuardDenied:
        def is_allowed(self, sub, act, res, ctx):
            return False

        def explain_sync(self, sub, act, res, ctx):
            return _Expl()

    dep = fl_mod.require_access(GuardDenied(), _build_env, add_headers=True)

    @dep
    def view(*args, **kwargs):
        return "OK"

    # Call with a dummy "request" as positional arg to exercise kwargs/args handling
    res = view(object())

    # Expect (jsonified payload, 403, headers). Headers must be empty due to falsy reason/rule_id/policy_id.
    assert isinstance(res, tuple) and len(res) == 3
    payload, status, headers = res
    assert payload == {"detail": "forbidden", "reason": None}
    assert status == 403
    assert headers == {}
