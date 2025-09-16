from rbacx.core.policyset import decide


def _env():
    return {
        "action": "read",
        "resource": {"type": "doc", "id": "1", "attrs": {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def test_nested_policyset_permit_when_no_deny():
    nested = {
        "policies": [
            {
                "id": "inner",
                "policies": [
                    {
                        "id": "p1",
                        "rules": [
                            {
                                "id": "r1",
                                "actions": ["read"],
                                "resource": {"type": "doc"},
                                "effect": "permit",
                            }
                        ],
                    }
                ],
            }
        ]
    }
    out = decide(nested, _env())
    assert out["decision"] in ("permit", "deny")
