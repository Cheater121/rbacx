# Tests for DSL linter edge cases.
# Note: Comments are in English by project rule.
from rbacx.dsl import lint


def test_first_applicable_unreachable_detected():
    """
    In 'first-applicable', a later rule that has the same selector as an earlier rule
    (same actions/resource) and the same effect is effectively unreachable.
    This aligns with typical linter behavior that flags shadowed rules.
    """
    policy = {
        "algorithm": "first-applicable",
        "rules": [
            {"id": "A", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"},
            {"id": "B", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"},
        ],
    }
    issues = lint.analyze_policy(policy)
    codes = {i.get("code") for i in issues}
    assert "POTENTIALLY_UNREACHABLE" in codes
