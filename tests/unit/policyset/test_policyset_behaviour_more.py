
from rbacx.core.policyset import decide

def env(action="read", rtype="doc", rid="1", attrs=None):
    return {
        "subject": {"id":"u","roles":[],"attrs":{}},
        "action": action,
        "resource": {"type": rtype, "id": rid, "attrs": attrs or {}},
        "context": {},
    }

def pol(effect, rid="1", obligations=None, rdef=None):
    rule = {"id": f"r{rid}{effect[0]}", "actions": ["read"], "effect": effect,
            "resource": rdef or {"type": "doc", "id": rid}}
    if obligations:
        rule["obligations"] = obligations
    return {"rules":[rule]}

def test_not_applicable_when_no_match_any_policy():
    ps = {"algorithm": "deny-overrides", "policies": [pol("permit", "2"), pol("deny", "3")]}
    res = decide(ps, env(rid="1"))
    assert res["decision"] in {"not_applicable", "deny"}

def test_obligations_propagated_from_selected_policy():
    ps = {"algorithm":"first-applicable", "policies":[pol("permit","1", obligations=[{"type":"m"}]) ]}
    res = decide(ps, env())
    assert res["decision"] == "permit"
    assert res.get("obligations") == [{"type":"m"}]
