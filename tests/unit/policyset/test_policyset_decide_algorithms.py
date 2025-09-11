
from rbacx.core.policyset import decide as decide_ps

def env(action="read", rtype="doc", rid="1", attrs=None):
    return {
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "action": action,
        "resource": {"type": rtype, "id": rid, "attrs": attrs or {}},
        "context": {},
    }

def pol(effect, rid="1"):
    return {"rules": [{"id": f"r{rid}{effect[0]}", "actions": ["read"], "effect": effect, "resource": {"type": "doc", "id": rid}}]}

def test_policyset_deny_overrides_and_permit_overrides_and_first_applicable():
    ps = {"algorithm": "deny-overrides", "policies": [pol("permit", "1"), pol("deny", "1")]}
    res = decide_ps(ps, env())
    assert res["decision"] == "deny"

    ps2 = {"algorithm": "permit-overrides", "policies": [pol("deny", "1"), pol("permit", "1")]}
    res2 = decide_ps(ps2, env())
    assert res2["decision"] == "permit"

    ps3 = {"algorithm": "first-applicable", "policies": [pol("permit", "1"), pol("deny", "1")]}
    res3 = decide_ps(ps3, env())
    assert res3["decision"] == "permit"
