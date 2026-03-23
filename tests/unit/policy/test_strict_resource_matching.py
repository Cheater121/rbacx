# Tests for strict_types=True correctness in match_resource().
#
# Bug fixed in 1.8.1: match_resource() was reading __strict_types__ from the
# nested `resource` sub-dict instead of the top-level env dict, so strict mode
# was silently ignored during resource matching even when Guard(strict_types=True).

from rbacx.core.policy import evaluate, match_resource

# ---------------------------------------------------------------------------
# match_resource() unit tests — strict flag passed explicitly
# ---------------------------------------------------------------------------


def test_match_resource_lax_coerces_type():
    """In lax mode, resource type is compared as string — int 1 matches str '1'."""
    rdef = {"type": "1"}
    resource = {"type": 1}
    assert match_resource(rdef, resource, strict=False) is True


def test_match_resource_strict_rejects_type_mismatch():
    """In strict mode, resource type must be exactly str — int does not match str."""
    rdef = {"type": "doc"}
    resource = {"type": "doc"}
    assert match_resource(rdef, resource, strict=True) is True

    rdef_int = {"type": "1"}
    resource_int = {"type": 1}
    assert match_resource(rdef_int, resource_int, strict=True) is False


def test_match_resource_strict_rejects_id_type_mismatch():
    """In strict mode, resource id must match exactly without str() coercion."""
    rdef = {"id": "42"}
    resource_str = {"type": "doc", "id": "42"}
    resource_int = {"type": "doc", "id": 42}

    assert match_resource(rdef, resource_str, strict=True) is True
    assert match_resource(rdef, resource_int, strict=True) is False


def test_match_resource_lax_coerces_id():
    """In lax mode, id 42 (int) matches rule id '42' (str) via str() coercion."""
    rdef = {"id": "42"}
    resource = {"type": "doc", "id": 42}
    assert match_resource(rdef, resource, strict=False) is True


def test_match_resource_strict_attr_exact_equality():
    """In strict mode, attribute values must match exactly — no str() coercion."""
    rdef = {"attrs": {"level": 2}}
    resource_match = {"type": "doc", "attrs": {"level": 2}}
    resource_nomatch = {"type": "doc", "attrs": {"level": "2"}}

    assert match_resource(rdef, resource_match, strict=True) is True
    assert match_resource(rdef, resource_nomatch, strict=True) is False


def test_match_resource_lax_attr_coerces():
    """In lax mode, attribute value 2 (int) matches rule value '2' (str)."""
    rdef = {"attrs": {"level": "2"}}
    resource = {"type": "doc", "attrs": {"level": 2}}
    assert match_resource(rdef, resource, strict=False) is True


# ---------------------------------------------------------------------------
# evaluate() integration — __strict_types__ must flow from env into match_resource
# ---------------------------------------------------------------------------


def _env(rtype, rid=None, attrs=None, strict=False):
    """Build a minimal env dict as the engine does."""
    e = {
        "subject": {"id": "u1", "roles": [], "attrs": {}},
        "action": "read",
        "resource": {"type": rtype, "id": rid, "attrs": attrs or {}},
        "context": {},
    }
    if strict:
        e["__strict_types__"] = True
    return e


def test_evaluate_strict_resource_type_mismatch_denies():
    """With __strict_types__ in env, int resource type must not match str rule type."""
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "r1",
                "actions": ["read"],
                "effect": "permit",
                # rule declares type as string "doc"
                "resource": {"type": "doc"},
            }
        ],
    }
    # Resource type is the string "doc" — should match in strict mode
    env_match = _env("doc", strict=True)
    res = evaluate(policy, env_match)
    assert res["decision"] == "permit", "string 'doc' must match rule type 'doc' in strict mode"

    # Resource type is int 1 — must NOT match string "1" in strict mode
    policy_int = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "r1",
                "actions": ["read"],
                "effect": "permit",
                "resource": {"type": "1"},
            }
        ],
    }
    env_int_strict = _env(1, strict=True)
    res2 = evaluate(policy_int, env_int_strict)
    assert res2["decision"] == "deny", (
        "int resource type must not match str rule type in strict mode; "
        "this was broken before 1.8.1 because __strict_types__ was read from "
        "the nested resource dict instead of the top-level env"
    )


def test_evaluate_lax_resource_type_int_matches_str():
    """Without strict mode, int resource type matches str rule type via coercion."""
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "r1",
                "actions": ["read"],
                "effect": "permit",
                "resource": {"type": "1"},
            }
        ],
    }
    env = _env(1, strict=False)
    res = evaluate(policy, env)
    assert res["decision"] == "permit"


def test_evaluate_strict_attr_value_mismatch_denies():
    """In strict mode, attribute value int 2 must not match rule value str '2'."""
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "r1",
                "actions": ["read"],
                "effect": "permit",
                "resource": {"type": "doc", "attrs": {"level": "2"}},
            }
        ],
    }
    # int attr value — must not match str rule attr in strict mode
    env_strict = _env("doc", attrs={"level": 2}, strict=True)
    res = evaluate(policy, env_strict)
    assert (
        res["decision"] == "deny"
    ), "int attr value must not match str rule attr value in strict mode"

    # same but lax — should match
    env_lax = _env("doc", attrs={"level": 2}, strict=False)
    res2 = evaluate(policy, env_lax)
    assert res2["decision"] == "permit"
