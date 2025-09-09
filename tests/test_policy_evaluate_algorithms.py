
from rbacx.core.policy import evaluate

def env(action="read", rtype="doc", rid="1", attrs=None):
    return {
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "action": action,
        "resource": {"type": rtype, "id": rid, "attrs": attrs or {}},
        "context": {},
    }

def test_evaluate_invalid_rules_type_returns_default():
    res = evaluate({"rules": {}}, env())
    assert res["decision"] == "deny"
    assert res["reason"] == "no_match"
    assert res["rule_id"] is None

def test_deny_overrides_and_permit_overrides():
    pol = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "p1", "actions": ["read"], "effect": "permit", "resource": {"type": "doc"}},
            {"id": "d1", "actions": ["read"], "effect": "deny", "resource": {"type": "doc"}},
        ],
    }
    res = evaluate(pol, env())
    assert res["decision"] == "deny"
    assert res["reason"] == "explicit_deny"

    pol2 = dict(pol)
    pol2["algorithm"] = "permit-overrides"
    res2 = evaluate(pol2, env())
    assert res2["decision"] == "permit"
    assert res2["reason"] == "matched"

def test_first_applicable_breaks_on_first_match_and_obligations_kept():
    pol = {
        "algorithm": "first-applicable",
        "rules": [
            {"id": "p1", "actions": ["read"], "effect": "permit", "resource": {"type": "doc"}, "obligations": [{"type": "x"}]},
            {"id": "p2", "actions": ["read"], "effect": "deny", "resource": {"type": "doc"}},
        ],
    }
    res = evaluate(pol, env())
    assert res["decision"] == "permit"
    assert res["rule_id"] == "p1"
    assert res["obligations"] == [{"type": "x"}]
