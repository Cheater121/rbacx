from rbacx.core.policyset import decide

def env():
    return {"subject":{"id":"u","roles":[],"attrs":{}},"action":"read",
            "resource":{"type":"doc","id":"1","attrs":{}},"context":{}}

def test_policyset_empty_policies():
    res = decide({"algorithm":"deny-overrides","policies":[]}, env())
    assert res["decision"] in {"deny","not_applicable","indeterminate"}
    assert "policy_id" in res
