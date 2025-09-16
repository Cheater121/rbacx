from rbacx.core.policy import evaluate


def _env(action="read", res_id="1", attrs=None):
    return {
        "action": action,
        "resource": {"type": "doc", "id": res_id, "attrs": attrs or {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def test_evaluate_permit_overrides_and_deny_overrides():
    policy = {
        "rules": [
            {"id": "r1", "actions": ["read"], "resource": {"type": "doc"}, "effect": "deny"},
            {
                "id": "r2",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "effect": "permit",
                "obligations": [{"mask": ["secret"]}],
            },
        ]
    }
    env = _env()
    # deny-overrides (default) -> deny wins
    out1 = evaluate(policy, env)
    assert out1["decision"] == "deny" and out1["reason"] in ("explicit_deny", "matched")
    # permit-overrides -> permit wins and obligations propagate
    out2 = evaluate(policy, env, algorithm="permit-overrides")
    assert out2["decision"] == "permit" and out2["rule_id"] == "r2"
    assert out2["obligations"] == [{"mask": ["secret"]}]


def test_evaluate_first_applicable_and_no_match_reason():
    policy = {
        "algorithm": "first-applicable",
        "rules": [
            {
                "id": "r1",
                "actions": ["read"],
                "resource": {"type": "doc", "id": "X"},
                "effect": "permit",
            },
            {"id": "r2", "actions": ["read"], "resource": {"type": "doc"}, "effect": "deny"},
        ],
    }
    # first-applicable picks first matching rule (r2, since r1 mismatches id)
    out = evaluate(policy, _env())
    assert out["rule_id"] == "r2" and out["decision"] in ("deny", "permit")
    # no-match: different action
    out2 = evaluate(policy, _env(action="write"))
    assert out2["reason"] in ("no_match", "action_mismatch")
