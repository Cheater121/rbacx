from rbacx.core.compiler import compile as compile_policy
from rbacx.core.policy import evaluate as eval_policy
from rbacx.core.policyset import decide as decide_ps


def _env(action="read", res_type="doc", res_id="1"):
    return {
        "action": action,
        "resource": {"type": res_type, "id": res_id, "attrs": {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def test_compile_single_policy_equivalence_across_actions():
    policy = {
        "rules": [
            {"id": "r1", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"},
            {"id": "r2", "actions": ["write"], "resource": {"type": "doc"}, "effect": "deny"},
        ]
    }
    decider = compile_policy(policy)
    for act in ("read", "write", "delete"):
        env = _env(action=act)
        out_c = decider(env)
        out_e = eval_policy(policy, env)
        assert out_c["decision"] == out_e["decision"]


def test_compile_policyset_first_applicable_and_permit_overrides():
    policy_first = {
        "algorithm": "first-applicable",
        "rules": [
            {"id": "r1", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"},
            {"id": "r2", "actions": ["read"], "resource": {"type": "doc"}, "effect": "deny"},
        ],
    }
    policy_permit = {
        "algorithm": "permit-overrides",
        "rules": [
            {"id": "p1", "actions": ["read"], "resource": {"type": "doc"}, "effect": "deny"},
            {"id": "p2", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"},
        ],
    }
    ps = {"policies": [policy_first, policy_permit]}
    decider = compile_policy(ps)
    env = _env("read")
    out_c = decider(env)
    out_ref = decide_ps(ps, env)
    assert out_c["decision"] == out_ref["decision"]
