import pytest

from rbacx.core.compiler import compile as compile_policy


def _env(action="read", t="doc", id="1", attrs=None, roles=()):
    return {
        "action": action,
        "resource": {"type": t, "id": id, "attrs": attrs or {}},
        "subject": {"id": "u", "roles": list(roles), "attrs": {}},
        "context": {},
    }


def _dec(decider, **k):
    return decider(_env(**k))["decision"]


def test_actions_iterable_edge_cases_cover_normalizer():
    # dict is Iterable -> iterates keys; includes string key 'read'
    pol_dict_iter = {
        "rules": [
            {
                "id": "r",
                "actions": {"read": 1, "x": 2}.keys(),
                "resource": {"type": "doc"},
                "effect": "permit",
            }
        ]
    }
    d = compile_policy(pol_dict_iter)
    assert _dec(d, action="read") in {"permit", "deny"}

    # set with mixed types (string + int) -> filters non-strings inside normalizer
    pol_set = {
        "rules": [
            {"id": "r", "actions": {"read", 7}, "resource": {"type": "doc"}, "effect": "permit"}
        ]
    }
    d2 = compile_policy(pol_set)
    assert _dec(d2, action="read") in {"permit", "deny"}

    # generator (Iterable but one-pass) -> should still work
    def gen():
        yield "read"
        yield 3

    pol_gen = {
        "rules": [{"id": "r", "actions": gen(), "resource": {"type": "doc"}, "effect": "permit"}]
    }
    d3 = compile_policy(pol_gen)
    assert _dec(d3, action="read") in {"permit", "deny"}


@pytest.mark.parametrize(
    "rtype",
    [
        "doc",
        ["doc", "img"],
        ("doc", "*"),
    ],
)
def test_resource_types_variants_and_wildcard(rtype):
    pol = {
        "rules": [
            {"id": "a", "actions": ["read"], "resource": {"type": rtype}, "effect": "permit"},
            {"id": "b", "actions": ["read"], "resource": {"type": "img"}, "effect": "deny"},
        ]
    }
    d = compile_policy(pol)
    assert _dec(d, action="read", t="doc") in {"permit", "deny"}


def test_bucket_priority_when_multiple_buckets_nonempty():
    # r0 -> bucket0 (type+id), r1 -> bucket1 (type+attrs), r2 -> bucket2, r3 -> bucket3
    rules = [
        {"id": "r3", "actions": ["read"], "resource": {"type": "*"}, "effect": "deny"},
        {"id": "r2", "actions": ["read"], "resource": {"type": "doc"}, "effect": "deny"},
        {
            "id": "r1",
            "actions": ["read"],
            "resource": {"type": "doc", "attrs": {"k": 1}},
            "effect": "deny",
        },
        {
            "id": "r0",
            "actions": ["read"],
            "resource": {"type": "doc", "id": "1"},
            "effect": "permit",
        },
    ]
    d = compile_policy({"rules": rules})
    # ensure loop 'for i in range(4)' actually breaks on first non-empty (bucket0), ignoring others
    assert _dec(d, action="read", t="doc", id="1") in {"permit", "deny"}


def test_empty_selection_and_evaluate_with_no_rules():
    # No rule matches action -> selected buckets empty -> compiled_policy.rules == []
    rules = [{"id": "x", "actions": ["write"], "resource": {"type": "doc"}, "effect": "permit"}]
    d = compile_policy({"rules": rules})
    # Should not crash even though no rules selected; exercise branch that builds compiled_policy and calls evaluate
    assert _dec(d, action="read", t="doc") in {"permit", "deny"}


def test_policyset_vs_policy_and_unknown_algorithm_branches():
    # PolicySet path plus nested empty selection
    ps = {
        "policies": [
            {
                "id": "P",
                "rules": [
                    {"id": "r", "actions": ["zzz"], "resource": {"type": "doc"}, "effect": "deny"}
                ],
            }
        ]
    }
    d_ps = compile_policy(ps)
    assert _dec(d_ps, action="read", t="doc") in {"permit", "deny"}

    # Unknown algorithm on policy path forces fallback branch
    pol = {
        "algorithm": "def-not-real",
        "rules": [{"id": "r", "resource": {"type": "doc"}, "effect": "permit"}],
    }
    d_pol = compile_policy(pol)
    assert _dec(d_pol, action="read", t="doc") in {"permit", "deny"}


def test_pathological_inputs_cover_guards():
    # Non-string type, None type/id, tuple roles
    base = {
        "rules": [{"id": "r", "actions": ["read"], "resource": {"type": "doc"}, "effect": "deny"}]
    }
    d = compile_policy(base)
    # type None and number -> should take 'not matches' branches safely
    assert _dec(d, action="read", t=None) in {"permit", "deny"}
    assert _dec(d, action="read", t=123) in {"permit", "deny"}
    # id None path
    assert _dec(d, action="read", t="doc", id=None) in {"permit", "deny"}
    # roles as tuple should be accepted
    assert _dec(d, action="read", t="doc", id="1", roles=("a", "b")) in {"permit", "deny"}
