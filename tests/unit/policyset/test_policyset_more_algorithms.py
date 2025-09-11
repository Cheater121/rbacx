
from rbacx.core.policyset import decide

def env(action="read", rtype="doc", rid="1"):
    return {"subject":{"id":"u","roles":[],"attrs":{}},
            "action":action,
            "resource":{"type":rtype,"id":rid,"attrs":{}},
            "context":{}}

def rule(effect, rid="1"):
    return {"id": f"{effect}-{rid}", "actions":["read"], "effect": effect, "resource":{"type":"doc","id":rid}}

def test_deny_overrides_returns_deny():
    ps = {"algorithm":"deny-overrides", "policies":[{"rules":[rule("permit","1"), rule("deny","1")]}]}
    res = decide(ps, env())
    assert res["decision"] == "deny"

def test_empty_policies_not_applicable():
    ps = {"algorithm":"first-applicable", "policies":[]}
    res = decide(ps, env())
    assert res["decision"] in {"not_applicable","deny"}  # depending on fallback, must not crash
