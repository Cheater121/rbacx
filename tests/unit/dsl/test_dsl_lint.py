
from rbacx.dsl.lint import analyze_policy, analyze_policyset

def test_analyze_policy_basic_issues():
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "r1", "actions": [], "resource": {"type": "*"}},    # empty actions + broad resource
            {"id": "", "actions": ["read"], "resource": {}},            # missing id + broad resource
            {"id": "r2", "actions": ["read"], "resource": {"type": "doc", "id": "1"}},
            {"id": "r2", "actions": ["read"], "resource": {"type": "doc", "id": "1"}},  # duplicate id & rid
            {"id": "r3", "actions": ["read"], "resource": {"type": "doc", "attrs": {"x": 1}}},
        ],
        "lint": {"require_attrs": {"doc": ["x", "y"]}}  # require attrs for permit rules
    }
    issues = analyze_policy(policy)
    codes = [i["code"] for i in issues]
    assert "EMPTY_ACTIONS" in codes
    assert "BROAD_RESOURCE" in codes
    assert "MISSING_ID" in codes
    assert "DUPLICATE_ID" in codes
    assert any(i["code"] == "REQUIRED_ATTRS" and i.get("missing") == ["y"] for i in issues)
    # deny-overrides overlap: add a deny that covers later permit
    policy2 = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "d1", "actions": ["read"], "effect": "deny", "resource": {"type": "doc"}},
            {"id": "p1", "actions": ["read"], "effect": "permit", "resource": {"type": "doc", "id": "1"}},
        ],
    }
    issues2 = analyze_policy(policy2)
    assert any(i["code"] == "OVERLAPPED_BY_DENY" for i in issues2)

def test_analyze_policyset_composes_policy_indexes():
    ps = {"policies": [
        {"rules": [{"id": "a", "actions": []}]},
        {"rules": [{"id": "b", "actions": []}]},
    ]}
    res = analyze_policyset(ps, require_attrs={"doc": ["id"]})
    assert all("policy_index" in i for i in res)
    assert {i["policy_index"] for i in res} == {0, 1}
