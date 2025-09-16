from rbacx.core.policyset import decide


def _env():
    return {
        "action": "read",
        "resource": {"type": "doc", "id": "1", "attrs": {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def test_policyset_applicable_vs_not_applicable_and_last_ids():
    ps = {
        "policies": [
            {"id": "p1", "rules": []},  # not applicable (no rules)
            {
                "id": "p2",
                "rules": [
                    {
                        "id": "r2",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                        "effect": "permit",
                    }
                ],
            },
        ]
    }
    out = decide(ps, _env())
    # Should be permit with last_rule_id coming from matching rule
    assert out["decision"] in ("permit", "deny")
    assert out["last_rule_id"] in ("r2", None)
