# Tests for compiler default algorithm consistency with policy.evaluate().
#
# Bug fixed in 1.8.1: compiler.compile() used "permit-overrides" as the default
# algorithm when the policy dict omits the "algorithm" key, while policy.evaluate()
# uses "deny-overrides". This caused compiled and interpreted paths to return
# different decisions for the same policy.

from rbacx.core.compiler import compile as compile_policy
from rbacx.core.policy import evaluate as evaluate_policy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env(action="read", rtype="doc", rid="1"):
    return {
        "subject": {"id": "u1", "roles": [], "attrs": {}},
        "action": action,
        "resource": {"type": rtype, "id": rid, "attrs": {}},
        "context": {},
    }


def _policy_no_algo():
    """Policy with both a permit and a deny rule, no explicit algorithm key."""
    return {
        "rules": [
            {"id": "p1", "actions": ["read"], "effect": "permit", "resource": {"type": "doc"}},
            {"id": "d1", "actions": ["read"], "effect": "deny", "resource": {"type": "doc"}},
        ]
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_compiled_and_interpreted_agree_on_default_algorithm():
    """Without an explicit 'algorithm' key, both paths must use deny-overrides.

    Before 1.8.1, compile() defaulted to permit-overrides while evaluate()
    defaulted to deny-overrides, so the same policy produced opposite decisions
    depending on whether the compiled fast-path was available.
    """
    policy = _policy_no_algo()
    env = _env()

    interpreted = evaluate_policy(policy, env)
    compiled_fn = compile_policy(policy)
    compiled = compiled_fn(env)

    assert interpreted["decision"] == compiled["decision"], (
        f"Compiled path returned '{compiled['decision']}' but interpreted "
        f"path returned '{interpreted['decision']}' for the same policy — "
        "default algorithms must be identical."
    )
    # Both must deny: deny-overrides is the conservative default.
    assert interpreted["decision"] == "deny"
    assert compiled["decision"] == "deny"


def test_explicit_deny_overrides_both_paths():
    """Explicit algorithm=deny-overrides must deny when both permit and deny rules match."""
    policy = {**_policy_no_algo(), "algorithm": "deny-overrides"}
    env = _env()

    assert evaluate_policy(policy, env)["decision"] == "deny"
    assert compile_policy(policy)(env)["decision"] == "deny"


def test_explicit_permit_overrides_both_paths():
    """Explicit algorithm=permit-overrides must permit when permit rule matches first."""
    policy = {**_policy_no_algo(), "algorithm": "permit-overrides"}
    env = _env()

    assert evaluate_policy(policy, env)["decision"] == "permit"
    assert compile_policy(policy)(env)["decision"] == "permit"


def test_no_algo_only_permit_rule_both_paths_agree():
    """When only a permit rule exists and no algorithm key, both paths permit."""
    policy = {
        "rules": [
            {"id": "p1", "actions": ["read"], "effect": "permit", "resource": {"type": "doc"}},
        ]
    }
    env = _env()

    interpreted = evaluate_policy(policy, env)
    compiled = compile_policy(policy)(env)

    assert interpreted["decision"] == "permit"
    assert compiled["decision"] == "permit"


def test_no_algo_only_deny_rule_both_paths_agree():
    """When only a deny rule exists and no algorithm key, both paths deny."""
    policy = {
        "rules": [
            {"id": "d1", "actions": ["read"], "effect": "deny", "resource": {"type": "doc"}},
        ]
    }
    env = _env()

    interpreted = evaluate_policy(policy, env)
    compiled = compile_policy(policy)(env)

    assert interpreted["decision"] == "deny"
    assert compiled["decision"] == "deny"
