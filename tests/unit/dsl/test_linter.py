
from rbacx.dsl.lint import analyze_policy

def test_missing_and_duplicate_ids_and_empty_actions():
    pol = {"algorithm":"first-applicable","rules":[
        {"id":"a","effect":"permit","actions":["read"],"resource":{"type":"doc"}},
        {"effect":"permit","actions":["read"],"resource":{"type":"doc"}},  # missing id
        {"id":"a","effect":"permit","actions":[],"resource":{"type":"*"}}, # duplicate id, empty actions, broad resource
        {"id":"b","effect":"permit","actions":["read"],"resource":{"type":"doc"}} # same shape as first -> potentially unreachable
    ]}
    issues = analyze_policy(pol)
    codes = {i["code"] for i in issues}
    assert "MISSING_ID" in codes
    assert "DUPLICATE_ID" in codes
    assert "EMPTY_ACTIONS" in codes
    assert "BROAD_RESOURCE" in codes
    assert "POTENTIALLY_UNREACHABLE" in codes
