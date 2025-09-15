from rbacx.core.compiler import compile as compile_policy


def _env(action="read", res_type="doc", res_id="1"):
    return {
        "action": action,
        "resource": {"type": res_type, "id": res_id, "attrs": {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def _has_decision(d):
    assert isinstance(d, dict) and d.get("decision") in {"permit", "deny"}


def test_compile_with_missing_rules_key_and_empty_policyset():
    # policy without 'rules' -> should not crash
    decider1 = compile_policy({})
    _has_decision(decider1(_env()))
    # policyset with non-list 'policies' -> fallback to empty -> no crash
    decider2 = compile_policy({"policies": None})
    _has_decision(decider2(_env()))


def test_compile_with_rule_without_actions_and_with_non_string_actions():
    policy = {
        "rules": [
            {"id": "r0", "resource": {"type": "doc"}, "effect": "permit"},  # no actions key
            {
                "id": "r1",
                "actions": [1, None, "read"],
                "resource": {"type": "doc"},
                "effect": "permit",
            },  # mixed types
        ]
    }
    decider = compile_policy(policy)
    _has_decision(decider(_env("read")))
    _has_decision(decider(_env("write")))


def test_compile_policyset_bucket_selection_and_continue_paths():
    # Craft a policyset with rules that should be filtered into different buckets
    ps = {
        "policies": [
            {
                "id": "p1",
                "rules": [
                    {"id": "a", "actions": ["read"], "resource": {"type": "doc"}, "effect": "deny"},
                    {
                        "id": "b",
                        "actions": ["write"],
                        "resource": {"type": "doc"},
                        "effect": "permit",
                    },
                ],
            },
            {
                "id": "p2",
                "rules": [
                    {
                        "id": "c",
                        "actions": ["read", "write", 123],
                        "resource": {"type": "doc"},
                        "effect": "permit",
                    },
                    {"id": "d", "actions": [], "resource": {"type": "doc"}, "effect": "permit"},
                ],
            },
        ]
    }
    decider = compile_policy(ps)
    # exercise several actions to traverse selection loop and continue logic
    for act in ("read", "write", "delete"):
        _has_decision(decider(_env(act)))


def test_compile_handles_weird_env_values_without_crash():
    decider = compile_policy(
        {"rules": [{"id": "r", "resource": {"type": "doc"}, "effect": "deny"}]}
    )
    # action not string; resource missing id; attrs not dict — should not crash
    env = {
        "action": 123,
        "resource": {"type": "doc", "id": None, "attrs": []},
        "subject": {"id": "u", "roles": (), "attrs": {}},
        "context": {},
    }
    _has_decision(decider(env))
