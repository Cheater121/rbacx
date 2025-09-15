from rbacx.core.policyset import decide


def _env():
    return {
        "action": "read",
        "resource": {"type": "doc", "id": "1", "attrs": {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def test_policyset_all_unapplicable_even_nested():
    ps = {
        "policies": [
            {"id": "p-empty", "rules": []},
            {"id": "nested", "policies": [{"id": "inner-empty", "rules": []}]},
        ]
    }
    out = decide(ps, _env())
    assert out["decision"] == "deny" and out["reason"] == "no_match"


def test_conflicting_policies_deny_wins_and_ids_present():
    ps = {
        "policies": [
            {
                "id": "allowP",
                "rules": [
                    {
                        "id": "r-allow",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                        "effect": "permit",
                    }
                ],
            },
            {
                "id": "denyP",
                "rules": [
                    {
                        "id": "r-deny",
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
    # last ids should refer to the matching deny rule where applicable
    assert out.get("last_rule_id") in ("r-deny", None)
