"""Tests covering the two remaining branches in compiler.py (v1.9.3).

Branch 1 — ``_action_matches``, line 80:
    ``if not isinstance(acts_raw, Iterable): return False``
    Reached when a rule carries a non-iterable ``actions`` value (e.g. an int).

Branch 2 — ``_select_rules`` / first-applicable dedup, line 133:
    ``if oid in seen: continue``
    Reached when the same rule object appears more than once in ``all_rules``
    under the ``first-applicable`` algorithm.
"""

from rbacx.core.compiler import _action_matches, _select_rules


def test_action_matches_returns_false_for_non_iterable_actions() -> None:
    """_action_matches must return False when rule.actions is not iterable.

    Covers the ``if not isinstance(acts_raw, Iterable): return False`` branch
    (compiler.py line 80).  An integer is not an Iterable, so the guard fires
    immediately and the function returns False without attempting membership
    tests.
    """
    rule = {"id": "r", "effect": "permit", "actions": 42, "resource": {}}
    assert _action_matches(rule, "read") is False


def test_select_rules_first_applicable_deduplicates_repeated_rule_object() -> None:
    """_select_rules must not include the same rule object twice under first-applicable.

    Covers the ``if oid in seen: continue`` branch (compiler.py line 133).
    The ``seen`` set tracks ``id(rule)`` so that if the exact same object
    appears more than once in ``all_rules`` (which can happen when a caller
    passes a list with a duplicated reference), it is emitted only once.
    """
    rule = {"id": "r", "effect": "permit", "actions": ["read"], "resource": {}}
    # Pass the same object twice — second occurrence must be skipped.
    all_rules = [rule, rule]
    selected = _select_rules(all_rules, [], None, "read", "first-applicable")
    assert len(selected) == 1
    assert selected[0] is rule
