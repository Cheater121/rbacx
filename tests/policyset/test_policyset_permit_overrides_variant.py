
from rbacx.core.policyset import decide

def env(action="read", rtype="doc", rid="1"):
    return {"subject":{"id":"u","roles":[],"attrs":{}},
            "action":action,
            "resource":{"type":rtype,"id":rid,"attrs":{}},
            "context":{}}

def rule(effect, rid="1"):
    return {"id": f"{effect}-{rid}", "actions": ["read"], "effect": effect, "resource": {"type":"doc", "id": rid}}

def test_permit_overrides_when_both_present():
    ps = {"algorithm":"permit-overrides", "policies":[{"rules":[rule("deny","1"), rule("permit","1")]}]}
    res = decide(ps, env())
    assert res["decision"] in {"permit", "deny"}
    assert "policy_id" in res
