# -*- coding: utf-8 -*-

from rbacx.dsl.lint import (
    _actions,
    _first_applicable_unreachable,
    _resource_covers,
    _rtype,
    analyze_policy,
)


# ---------- 18->17: for-loop back-edge in _actions (dedupe keeps first, skips duplicate) ----------
def test__actions_dedup_and_loop_backedge():
    rule = {"actions": ["read", "write", "read", 123, None]}
    assert _actions(rule) == ("read", "write")  # duplicate "read" skipped


# ---------- 31-32: list type -> normalized & sorted join; empty list (or all Nones) -> None ----------
def test__rtype_list_normalization_and_empty_list():
    # sorted + joined
    rule1 = {"resource": {"type": ["b", "a", None]}}
    assert _rtype(rule1) == "a,b"
    # only None values -> None
    rule2 = {"resource": {"type": [None, None]}}
    assert _rtype(rule2) is None


# ---------- 71: attrs not dict -> early True ----------
def test__resource_covers_when_attrs_not_dict_returns_true():
    earlier = {"resource": {"type": "doc", "attrs": "oops"}}  # not a dict
    later = {"resource": {"type": "doc", "attrs": {"x": 1}}}
    assert _resource_covers(earlier, later) is True


# ---------- 73-76: missing key -> False; value mismatch -> False ----------
def test__resource_covers_missing_key_returns_false():
    earlier = {"resource": {"type": "doc", "attrs": {"x": 1}}}
    later = {"resource": {"type": "doc", "attrs": {"y": 1}}}  # no "x"
    assert _resource_covers(earlier, later) is False


def test__resource_covers_value_mismatch_returns_false():
    earlier = {"resource": {"type": "doc", "attrs": {"x": 1}}}
    later = {"resource": {"type": "doc", "attrs": {"x": 2}}}  # mismatch on "x"
    assert _resource_covers(earlier, later) is False


# ---------- 82: effect mismatch -> False ----------
def test__first_applicable_unreachable_effect_mismatch_false():
    earlier = {"effect": "deny", "actions": ["read"], "resource": {"type": "doc"}}
    later = {"effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}
    assert _first_applicable_unreachable(earlier, later) is False


# ---------- 86: later actions not subset of earlier -> False ----------
def test__first_applicable_unreachable_actions_not_subset_false():
    earlier = {"effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}
    later = {"effect": "permit", "actions": ["read", "write"], "resource": {"type": "doc"}}
    assert _first_applicable_unreachable(earlier, later) is False


# ---------- 108: analyze_policy returns immediately when rules is not a list ----------
def test_analyze_policy_rules_not_list_returns_empty():
    pol = {"algorithm": "deny-overrides", "rules": {"not": "a list"}}
    assert analyze_policy(pol) == []


# ---------- 173->171: deny-overrides loop where _resource_covers is False (skip to next later) ----------
def test_deny_overrides_resource_not_covered_no_issue():
    pol = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "d1", "effect": "deny", "actions": ["read"], "resource": {"type": "doc"}},
            {
                "id": "p1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "img"},
            },  # different type
        ],
    }
    issues = analyze_policy(pol)
    # No OVERLAPPED_BY_DENY because resource doesn't cover the later rule
    assert not any(it["code"] == "OVERLAPPED_BY_DENY" for it in issues)


# ---------- 174->171: deny-overrides loop where covers=True but action sets don't intersect (skip) ----------
def test_deny_overrides_no_action_overlap_no_issue():
    pol = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "d1", "effect": "deny", "actions": ["read"], "resource": {"type": "doc"}},
            {
                "id": "p1",
                "effect": "permit",
                "actions": ["write"],
                "resource": {"type": "doc"},
            },  # same type
        ],
    }
    issues = analyze_policy(pol)
    # Covers by resource, but no action overlap -> no issue emitted
    assert not any(it["code"] == "OVERLAPPED_BY_DENY" for it in issues)


# ---------- 12: _actions returns empty tuple when actions is not Iterable ----------
def test__actions_non_iterable_returns_empty():
    rule = {"actions": 42}  # not an Iterable of strings
    assert _actions(rule) == ()


# ---------- 75->72: first attr matches (loop continues), second attr fails (missing) ----------
def test__resource_covers_loop_backedge_then_missing_key():
    earlier = {"resource": {"type": "doc", "attrs": {"x": 1, "y": 2}}}
    # 'x' present and equal -> loop continues; 'y' missing -> returns False
    later = {"resource": {"type": "doc", "attrs": {"x": 1}}}
    assert _resource_covers(earlier, later) is False
