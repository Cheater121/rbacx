from rbacx.core.compiler import _actions
from rbacx.core.compiler import compile as compile_policy
from rbacx.core.policyset import decide as decide_policyset


def test__actions_filters_non_strings_and_non_iterable():
    assert _actions({"actions": ["read", 1, None, "write"]}) == ("read", "write")
    assert _actions({"actions": 123}) == ()


def test_compile_returns_decider_for_policyset_and_policy():
    env = {
        "action": "read",
        "resource": {"type": "doc", "id": "1", "attrs": {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }
    policyset = {
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
        ]
    }
    decider = compile_policy(policyset)
    out = decider(env)
    ref = decide_policyset(policyset, env)
    assert out["decision"] == ref["decision"]
