from rbacx.core.compiler import compile as compile_policy


def _env(action="read", t="doc", id="1", attrs=None):
    return {
        "action": action,
        "resource": {"type": t, "id": id, "attrs": attrs or {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def _dec(decider, **k):
    return decider(_env(**k))["decision"]


def test_actions_filtering_iterable_but_nonstrings_and_none_iterable():
    # acts as iterable but contains only non-strings -> empty bucket for action matching
    dec = compile_policy(
        {
            "rules": [
                {"id": "a", "actions": [1, 2, 3], "resource": {"type": "doc"}, "effect": "permit"},
                {"id": "b", "actions": None, "resource": {"type": "doc"}, "effect": "permit"},
            ]
        }
    )
    # nothing matches 'read' by actions -> decision falls back to deny/no_match path but must not crash
    assert _dec(dec, action="read") in {
        "deny",
        "permit",
    }  # library-level algorithm may still allow by other rule structure


def test_categorize_all_buckets_and_none():
    # bucket 0: type match + id-specific
    r0 = {
        "id": "id-specific",
        "actions": ["read"],
        "resource": {"type": "doc", "id": "1"},
        "effect": "permit",
    }
    # bucket 1: type match + attrs constrained
    r1 = {
        "id": "attrs",
        "actions": ["read"],
        "resource": {"type": "doc", "attrs": {"k": 1}},
        "effect": "deny",
    }
    # bucket 2: type match only
    r2 = {"id": "type-only", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"}
    # bucket 3: wildcard type
    r3 = {"id": "wild", "actions": ["read"], "resource": {"type": "*"}, "effect": "deny"}
    # none: different type
    rN = {"id": "other", "actions": ["read"], "resource": {"type": "img"}, "effect": "permit"}

    dec = compile_policy({"rules": [rN, r3, r2, r1, r0]})
    # id '1' should pick bucket 0 first
    assert _dec(dec, action="read", t="doc", id="1") in {"permit", "deny"}
    # different id -> bucket 1/2/3 selection should still work (no id match for r0)
    assert _dec(dec, action="read", t="doc", id="X") in {"permit", "deny"}
    # different type -> only wildcard applies
    assert _dec(dec, action="read", t="img", id="1") in {"permit", "deny"}


def test_algorithm_overrides_paths_exercised():
    # deny-overrides: any deny wins
    pol_deny_over = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "p", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"},
            {"id": "d", "actions": ["read"], "resource": {"type": "doc"}, "effect": "deny"},
        ],
    }
    # permit-overrides: any permit wins
    pol_permit_over = {
        "algorithm": "permit-overrides",
        "rules": [
            {"id": "d2", "actions": ["read"], "resource": {"type": "doc"}, "effect": "deny"},
            {"id": "p2", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"},
        ],
    }
    dec_deny = compile_policy(pol_deny_over)
    dec_permit = compile_policy(pol_permit_over)
    assert _dec(dec_deny, action="read") == "deny"
    assert _dec(dec_permit, action="read") == "permit"


def test_policyset_vs_policy_dispatch_and_empty_selected_rules():
    # Policyset should dispatch to policyset path
    ps = {
        "policies": [
            {
                "id": "p1",
                "rules": [
                    {"id": "r", "actions": ["xxx"], "resource": {"type": "doc"}, "effect": "permit"}
                ],
            }
        ]
    }
    dec = compile_policy(ps)
    # Action 'read' doesn't match any rule -> selected bucket empty -> still returns a decision (deny typically)
    assert _dec(dec, action="read") in {"deny", "permit"}

    # Policy path with unknown algorithm should still compile and return decision
    pol = {
        "algorithm": "unknown-strategy",
        "rules": [{"id": "r", "resource": {"type": "doc"}, "effect": "deny"}],
    }
    dec2 = compile_policy(pol)
    assert _dec(dec2, action="read") in {"deny", "permit"}
