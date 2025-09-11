
from rbacx.dsl.lint import analyze_policy

def test_overlapped_by_deny_and_required_and_dup_id():
    pol = {
        "algorithm":"deny-overrides",
        "lint": {"require_attrs": {"doc":["tenant"]}},
        "rules":[
            {"id":"deny_all_doc","effect":"deny","actions":["read","write"],"resource":{"type":"doc"}},  # early broad deny
            {"id":"permit_one","effect":"permit","actions":["read"],"resource":{"type":"doc","attrs":{"tenant":"t1"}}},
            {"id":"dup1","effect":"deny","actions":["read"],"resource":{"type":"doc","id":"123"}},
            {"id":"dup2","effect":"deny","actions":["read"],"resource":{"type":"doc","id":"123"}}
        ]
    }
    issues = analyze_policy(pol)
    codes = {i["code"] for i in issues}
    assert "OVERLAPPED_BY_DENY" in codes
    assert "REQUIRED_ATTRS" not in codes  # 'permit_one' has required attr
    # but if we remove attr, it should warn
    pol["rules"][1]["resource"].pop("attrs")
    issues2 = analyze_policy(pol)
    codes2 = {i["code"] for i in issues2}
    assert "REQUIRED_ATTRS" in codes2
    assert "DUPLICATE_RESOURCE_ID" in codes2
