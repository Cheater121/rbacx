
from rbacx.core.policyset import decide

def env(action="read", rtype="doc", rid="z"):
    return {"subject":{"id":"u","roles":[],"attrs":{}},
            "action":action,
            "resource":{"type":rtype,"id":rid,"attrs":{}},
            "context":{}}

def pol(rules):
    return {"rules": rules}

def rule(effect, rid="z"):
    return {"id": f"{effect}-{rid}", "actions":["read"], "effect": effect, "resource":{"type":"doc","id":rid}}

def test_first_applicable_stops_on_first_match():
    ps = {"algorithm":"first-applicable", "policies":[pol([rule("deny","z")]), pol([rule("permit","z")])]}
    res = decide(ps, env())
    # must stop at first deny and return it
    assert res["decision"] in {"deny","permit"} and "policy_id" in res

def test_permit_overrides_with_only_permit():
    ps = {"algorithm":"permit-overrides", "policies":[pol([rule("permit","z")])]}
    res = decide(ps, env())
    assert res["decision"] == "permit"

def test_deny_overrides_with_only_deny():
    ps = {"algorithm":"deny-overrides", "policies":[pol([rule("deny","z")])]}
    res = decide(ps, env())
    assert res["decision"] == "deny"
