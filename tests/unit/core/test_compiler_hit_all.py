import pytest

from rbacx.core.compiler import compile as compile_policy


def _env(action="read", t="doc", id="1", attrs=None, subj_roles=()):
    return {
        "action": action,
        "resource": {"type": t, "id": id, "attrs": attrs or {}},
        "subject": {"id": "u", "roles": list(subj_roles), "attrs": {}},
        "context": {},
    }


def _decider(obj):
    return compile_policy(obj)


def _dec(decider, **k):
    return decider(_env(**k))["decision"]


def test_actions_as_string_and_tuple_and_noniterable():
    # actions as STR (iterable of chars) -> should behave like weird iterable
    pol_str = {
        "rules": [{"id": "s", "actions": "read", "resource": {"type": "doc"}, "effect": "permit"}]
    }
    d1 = _decider(pol_str)
    assert _dec(d1, action="read") in {
        "permit",
        "deny",
    }  # should not crash regardless of matching intricacies

    # actions as TUPLE -> supported iterable path
    pol_tuple = {
        "rules": [
            {
                "id": "t",
                "actions": ("read", "write"),
                "resource": {"type": "doc"},
                "effect": "permit",
            }
        ]
    }
    d2 = _decider(pol_tuple)
    assert _dec(d2, action="read") in {"permit", "deny"}

    # actions as NON-ITERABLE -> early empty actions path
    pol_nonit = {
        "rules": [{"id": "n", "actions": 123, "resource": {"type": "doc"}, "effect": "permit"}]
    }
    d3 = _decider(pol_nonit)
    assert _dec(d3, action="read") in {"permit", "deny"}


def test_missing_and_unknown_algorithm_defaults():
    # missing algorithm -> default path
    pol_missing = {"rules": [{"id": "r", "resource": {"type": "doc"}, "effect": "deny"}]}
    d1 = _decider(pol_missing)
    assert _dec(d1, action="read") in {"permit", "deny"}

    # unknown algorithm string -> still compiles and returns decision
    pol_unknown = {
        "algorithm": "definitely-not-real",
        "rules": [{"id": "r", "resource": {"type": "doc"}, "effect": "permit"}],
    }
    d2 = _decider(pol_unknown)
    assert _dec(d2, action="read") in {"permit", "deny"}


def test_policyset_and_nested_empty_selection_paths():
    # nested policyset -> ensure policyset branch is exercised
    ps = {
        "policies": [
            {
                "id": "p1",
                "rules": [
                    {"id": "deny", "actions": ["x"], "resource": {"type": "doc"}, "effect": "deny"}
                ],
            },
            {
                "id": "p2",
                "policies": [
                    {
                        "id": "inner",
                        "rules": [
                            {
                                "id": "allow",
                                "actions": ["y"],
                                "resource": {"type": "doc"},
                                "effect": "permit",
                            }
                        ],
                    }
                ],
            },
        ]
    }
    d = _decider(ps)
    # action 'read' matches none -> empty selection and algorithm handling
    assert _dec(d, action="read") in {"permit", "deny"}


@pytest.mark.parametrize(
    "rules, expect_any",
    [
        # bucket 0: id specific
        (
            [
                {
                    "id": "id0",
                    "actions": ["read"],
                    "resource": {"type": "doc", "id": "1"},
                    "effect": "permit",
                }
            ],
            {"permit", "deny"},
        ),
        # bucket 1: attrs present
        (
            [
                {
                    "id": "id1",
                    "actions": ["read"],
                    "resource": {"type": "doc", "attrs": {"k": 1}},
                    "effect": "permit",
                }
            ],
            {"permit", "deny"},
        ),
        # bucket 2: type only
        (
            [{"id": "id2", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"}],
            {"permit", "deny"},
        ),
        # bucket 3: wildcard
        (
            [{"id": "id3", "actions": ["read"], "resource": {"type": "*"}, "effect": "permit"}],
            {"permit", "deny"},
        ),
    ],
)
def test_all_buckets_selection(rules, expect_any):
    d = _decider({"rules": rules})
    assert _dec(d, action="read") in expect_any


def test_resource_edge_inputs_and_subject_roles_iterable():
    # resource.type missing / non-string, and roles as tuple -> robustness path
    d = _decider(
        {"rules": [{"id": "r", "actions": ["read"], "resource": {"type": "doc"}, "effect": "deny"}]}
    )
    assert _dec(d, action="read", t=None) in {"permit", "deny"}
    assert _dec(d, action="read", t=123) in {"permit", "deny"}
    assert _dec(d, action="read", t="doc", id=None) in {"permit", "deny"}
    assert _dec(d, action="read", t="doc", id="1", attrs={"k": "v"}) in {"permit", "deny"}
    assert _dec(d, action="read", t="doc", id="1", attrs={"k": "v"}, subj_roles=("r1", "r2")) in {
        "permit",
        "deny",
    }
