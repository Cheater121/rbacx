from rbacx.core.policyset import decide


def _env():
    return {
        "action": "read",
        "resource": {"type": "doc", "id": "1", "attrs": {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def test_explicit_deny_precedence_across_policies():
    ps = {
        "policies": [
            {
                "id": "p1",
                "rules": [
                    {
                        "id": "allow",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                        "effect": "permit",
                    }
                ],
            },
            {
                "id": "p2",
                "rules": [
                    {
                        "id": "deny",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                        "effect": "deny",
                    }
                ],
            },
        ]
    }
    out = decide(ps, _env())
    assert out["decision"] == "deny"
    assert out["policy_id"] in ("p2", None)


def test_nested_policies_all_not_applicable_returns_no_match():
    ps = {
        "policies": [
            {"id": "empty", "rules": []},
            {"id": "nested", "policies": [{"id": "inner", "rules": []}]},
        ]
    }
    out = decide(ps, _env())
    assert out["decision"] == "deny" and out["reason"] == "no_match"
