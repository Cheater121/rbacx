from rbacx.core.policyset import decide


def _env():
    return {
        "action": "read",
        "resource": {"type": "doc", "id": "1", "attrs": {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def test_policyset_explicit_deny_wins_and_no_match():
    ps = {
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
            },
            {
                "id": "p2",
                "rules": [
                    {"id": "r2", "actions": ["read"], "resource": {"type": "doc"}, "effect": "deny"}
                ],
            },
        ]
    }
    out = decide(ps, _env())
    assert out["decision"] == "deny" and out["policy_id"] == "p2"
    # no match at all
    ps2 = {
        "policies": [
            {
                "id": "p",
                "rules": [
                    {
                        "id": "r",
                        "actions": ["write"],
                        "resource": {"type": "doc"},
                        "effect": "permit",
                    }
                ],
            }
        ]
    }
    out2 = decide(ps2, _env())
    assert out2["decision"] == "deny" and out2["reason"] == "no_match"
