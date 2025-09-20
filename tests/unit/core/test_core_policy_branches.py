# -*- coding: utf-8 -*-
from datetime import datetime, timedelta, timezone

import pytest

from rbacx.core.policy import (
    ConditionTypeError,
    eval_condition,
    evaluate,
    match_actions,
    match_resource,
    resolve,
)

# ----------------------- helpers: match_actions / match_resource -----------------------


def test_match_actions_not_iterable_returns_false():
    # Covers: acts_raw not iterable -> False (line ~26)
    assert match_actions({"actions": None}, "read") is False


def test_match_actions_exact_and_star():
    # Covers: "action in acts" and "*" wildcard (line ~28)
    assert match_actions({"actions": ["read", "write"]}, "read") is True
    assert match_actions({"actions": ["*"]}, "whatever") is True
    # Non-string items are filtered out
    assert match_actions({"actions": ["read", 123]}, "read") is True


def test_match_resource_type_id_attrs_paths():
    # Covers type check with str and list (lines ~39-52), id equality, and attrs match
    res = {"type": "doc", "id": "42", "attrs": {"level": "high", "tags": "a"}}
    # r_type mismatch -> False
    assert match_resource({"type": "img"}, res) is False
    # r_type list with "*" -> skip strict type filter -> True later if others ok
    assert match_resource({"type": ["*"]}, res) is True
    # r_type non-str/list coerced to str
    assert match_resource({"type": 1, "id": "42"}, {"type": "1", "id": "42"}) is True
    # id mismatch -> False
    assert match_resource({"id": "99"}, res) is False
    # attrs: missing key -> False
    assert match_resource({"attrs": {"owner": "alice"}}, res) is False
    # attrs: list means one-of
    res2 = {"type": "doc", "id": "7", "attrs": {"level": "low", "tags": "b"}}
    assert match_resource({"attrs": {"tags": ["a", "b"]}}, res2) is True
    # attrs equality (stringified)
    assert match_resource({"attrs": {"level": "low"}}, res2) is True
    # rdef not dict -> False
    assert match_resource([], res) is False
    # res attrs not dict -> False
    assert match_resource({"attrs": {"k": "v"}}, {"attrs": 123}) is False
    # empty rdef -> True
    assert match_resource({}, res) is True


# ----------------------- helpers: resolve / ensure / parsing -----------------------


def test_resolve_path_from_env_dict_and_attr():
    # Covers dict {"attr": "a.b"} resolution and non-dict passthrough
    class Obj:
        def __init__(self):
            self.b = {"c": 5}

    env = {"a": Obj()}
    assert resolve({"attr": "a.b.c"}, env) == 5
    assert resolve(10, env) == 10


def test_ensure_numeric_strict_and_str_and_parse_dt():
    # _ensure_numeric_strict error on bool propagates through eval_condition ">" branch
    with pytest.raises(ConditionTypeError):
        eval_condition({">": [True, 1]}, {})
    # _ensure_str error propagates (startsWith with non-strings)
    with pytest.raises(ConditionTypeError):
        eval_condition({"startsWith": [1, 2]}, {})
    # _parse_dt paths via before/after and ISO 'Z' handling
    now = datetime.now(timezone.utc)
    earlier = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    later = (now + timedelta(hours=1)).timestamp()
    assert eval_condition({"before": [{"attr": "t"}, earlier]}, {"t": now}) is False
    assert eval_condition({"after": [{"attr": "t"}, later]}, {"t": now}) is False
    # Invalid ISO raises ConditionTypeError through eval_condition
    with pytest.raises(ConditionTypeError):
        eval_condition({"before": ["not-a-date", "2020-01-01T00:00:00Z"]}, {})


def test_as_collection_and_between_guard_raises():
    # _as_collection guard is used by hasAll/hasAny and between invalid range -> raises
    with pytest.raises(ConditionTypeError):
        eval_condition({"hasAll": [["a", "b"], 42]}, {})
    with pytest.raises(ConditionTypeError):
        eval_condition({"hasAny": [42, ["x"]]}, {})
    with pytest.raises(ConditionTypeError):
        eval_condition({"between": ["2024-01-01T00:00:00Z", ["only-one-bound"]]}, {})


# ----------------------- eval_condition operator matrix -----------------------


def test_eval_condition_equality_and_inequality_and_default():
    # Covers '==' and '!=' and default False
    assert eval_condition({"==": [1, 1]}, {}) is True
    assert eval_condition({"!=": [1, 2]}, {}) is True
    assert eval_condition({"__unknown__": [1, 2]}, {}) is False


def test_eval_condition_numeric_relations():
    # Covers >, <, >=, <= with numeric coercion
    assert eval_condition({">": [1, 0]}, {}) is True
    assert eval_condition({"<": [0, 1]}, {}) is True
    assert eval_condition({">=": [1, 1]}, {}) is True
    assert eval_condition({"<=": [1, 1]}, {}) is True


def test_eval_condition_contains_variants_and_mismatch():
    # list membership
    assert eval_condition({"contains": [[1, 2, 3], 2]}, {}) is True
    # substring
    assert eval_condition({"contains": ["foobar", "bar"]}, {}) is True
    # mismatch -> raises
    with pytest.raises(ConditionTypeError):
        eval_condition({"contains": [123, "x"]}, {})


def test_eval_condition_in_all_cases():
    # collection vs collection -> overlap
    assert eval_condition({"in": [[1, 2], [2, 3]]}, {}) is True
    # x2 is collection -> membership
    assert eval_condition({"in": [2, [1, 2, 3]]}, {}) is True
    # x1 is collection -> membership
    assert eval_condition({"in": [[1, 2, 3], 2]}, {}) is True
    # both strings -> substring
    assert eval_condition({"in": ["abc", "zabcz"]}, {}) is True
    # mismatch -> raises
    with pytest.raises(ConditionTypeError):
        eval_condition({"in": [1, 2]}, {})


def test_eval_condition_hasAll_hasAny_and_not_and_or():
    # hasAll / hasAny
    assert eval_condition({"hasAll": [[1, 2, 3], [2, 3]]}, {}) is True
    assert eval_condition({"hasAny": [[1, 2, 3], [9, 2]]}, {}) is True
    # startsWith / endsWith
    assert eval_condition({"startsWith": ["foobar", "foo"]}, {}) is True
    assert eval_condition({"endsWith": ["foobar", "bar"]}, {}) is True
    # and / or / not
    assert eval_condition({"and": [True, {"==": [1, 1]}]}, {}) is True
    assert eval_condition({"or": [False, {"==": [1, 1]}]}, {}) is True
    assert eval_condition({"not": {"==": [1, 2]}}, {}) is True
    # and/or type guard
    with pytest.raises(ConditionTypeError):
        eval_condition({"and": 123}, {})
    with pytest.raises(ConditionTypeError):
        eval_condition({"or": 123}, {})


# ----------------------- evaluate: algorithm branches and reasons -----------------------


def test_evaluate_rules_not_list_early_return():
    # Covers early return when rules is not a list (lines ~100/107/113-114 path setup)
    out = evaluate({"rules": {"id": "r1"}}, {})
    assert out["decision"] == "deny"
    assert out["reason"] == "no_match"
    assert out["rule_id"] is None
    assert out["last_rule_id"] is None
    assert out["obligations"] == []


def test_evaluate_action_mismatch_and_resource_mismatch_reasons():
    # Action mismatch -> reason set accordingly
    pol = {"rules": [{"id": "r1", "actions": ["read"]}]}
    out = evaluate(pol, {"action": "write", "resource": {"type": "doc"}})
    assert out["reason"] == "action_mismatch"
    # Resource mismatch -> reason set accordingly
    pol = {"rules": [{"id": "r1", "actions": ["read"], "resource": {"type": "doc"}}]}
    out = evaluate(pol, {"action": "read", "resource": {"type": "img"}})
    assert out["reason"] == "resource_mismatch"


def test_evaluate_condition_mismatch_and_type_mismatch():
    # condition evaluates to False -> condition_mismatch
    pol = {
        "rules": [{"id": "r1", "actions": ["read"], "resource": {}, "condition": {"==": [1, 2]}}]
    }
    out = evaluate(pol, {"action": "read", "resource": {}})
    assert out["reason"] == "condition_mismatch"
    # condition raises -> condition_type_mismatch
    pol = {
        "rules": [
            {"id": "r1", "actions": ["read"], "resource": {}, "condition": {"startsWith": [1, 2]}}
        ]
    }
    out = evaluate(pol, {"action": "read", "resource": {}})
    assert out["reason"] == "condition_type_mismatch"


def test_evaluate_first_applicable_permit_and_deny_breaks():
    # first-applicable with permit effect -> matched and break (line ~164)
    pol = {
        "algorithm": "first-applicable",
        "rules": [
            {
                "id": "p1",
                "actions": ["*"],
                "resource": {},
                "effect": "permit",
                "obligations": [{"k": "v"}],
            },
            {"id": "p2", "actions": ["*"], "resource": {}, "effect": "deny"},
        ],
    }
    out = evaluate(pol, {"action": "read", "resource": {}})
    assert out["decision"] == "permit"
    assert out["reason"] == "matched"
    assert out["last_rule_id"] == "p1"
    assert out["obligations"] == [{"k": "v"}]

    # first-applicable with deny -> explicit_deny and break
    pol["rules"][0]["effect"] = "deny"
    out = evaluate(pol, {"action": "read", "resource": {}})
    assert out["decision"] == "deny"
    assert out["reason"] == "explicit_deny"
    assert out["last_rule_id"] == "p1"


def test_evaluate_deny_overrides_immediate_break_and_obligations():
    # Under deny-overrides the loop breaks on the first deny, but the finalization
    # block resets obligations to [] regardless of what the rule had.
    pol = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "d1",
                "actions": ["*"],
                "resource": {},
                "effect": "deny",
                "obligations": [{"a": 1}],
            },
            {"id": "p1", "actions": ["*"], "resource": {}, "effect": "permit"},
        ],
    }
    out = evaluate(pol, {"action": "x", "resource": {}})
    assert out["decision"] == "deny"
    assert out["reason"] == "explicit_deny"
    assert out["last_rule_id"] == "d1"
    # Finalization resets obligations to []
    assert out["obligations"] == []

    # Also verify non-list obligations are normalized to [] (redundant but explicit)
    pol["rules"][0]["obligations"] = {"a": 1}
    out = evaluate(pol, {"action": "x", "resource": {}})
    assert out["obligations"] == []


def test_evaluate_permit_overrides_break_on_permit():
    pol = {
        "algorithm": "permit-overrides",
        "rules": [
            {
                "id": "p1",
                "actions": ["*"],
                "resource": {},
                "effect": "permit",
                "obligations": [{"ok": True}],
            },
            {"id": "d1", "actions": ["*"], "resource": {}, "effect": "deny"},
        ],
    }
    out = evaluate(pol, {"action": "x", "resource": {}})
    assert out["decision"] == "permit"
    assert out["reason"] == "matched"
    assert out["last_rule_id"] == "p1"
    assert out["obligations"] == [{"ok": True}]


def test_finalize_deny_overrides_any_permit_and_no_match_paths():
    # Only permits under deny-overrides without breaking -> finalize to permit (line ~227)
    pol = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "p1",
                "actions": ["*"],
                "resource": {},
                "effect": "permit",
                "obligations": [{"x": 1}],
            },
            {
                "id": "p2",
                "actions": ["*"],
                "resource": {},
                "effect": "permit",
                "obligations": [{"x": 2}],
            },
        ],
    }
    out = evaluate(pol, {"action": "y", "resource": {}})
    assert out["decision"] == "permit"
    assert out["reason"] == "matched"
    assert out["last_rule_id"] == "p2"  # last matched rule id
    assert out["obligations"] == [{"x": 2}]

    # No matches at all -> deny/no_match (line ~232)
    pol = {
        "algorithm": "deny-overrides",
        "rules": [{"id": "r1", "actions": ["read"], "resource": {}}],
    }
    out = evaluate(pol, {"action": "write", "resource": {}})
    assert out["decision"] == "deny"
    assert out["reason"] in {"no_match", "action_mismatch"}  # implementation keeps gathered reason
    assert out["obligations"] == []


def test_finalize_permit_overrides_any_deny_and_else_path():
    # Only denies under permit-overrides -> finalize deny/explicit_deny
    pol = {
        "algorithm": "permit-overrides",
        "rules": [{"id": "d1", "actions": ["*"], "resource": {}, "effect": "deny"}],
    }
    out = evaluate(pol, {"action": "z", "resource": {}})
    assert out["decision"] == "deny"
    assert out["reason"] == "explicit_deny"
    assert out["last_rule_id"] == "d1"

    # Unknown algorithm path (else branch) with no matches -> keep gathered reason and deny
    pol = {
        "algorithm": "something-else",
        "rules": [{"id": "r1", "actions": ["read"], "resource": {}}],
    }
    out = evaluate(pol, {"action": "write", "resource": {}})
    assert out["decision"] == "deny"
    # last_rule_id remains None because nothing matched
    assert out["last_rule_id"] is None


# ----------------------- misc: default paths and return -----------------------


def test_eval_condition_bool_and_default_false_and_return_shape():
    # Non-dict cond -> bool conversion
    assert eval_condition(True, {}) is True
    # Ensure the final result dict shape (covers final return ~265)
    pol = {"rules": [{"id": "p1", "actions": ["*"], "resource": {}, "effect": "permit"}]}
    out = evaluate(pol, {"action": "anything", "resource": {}})
    keys = {"decision", "reason", "rule_id", "last_rule_id", "obligations"}
    assert set(out.keys()) == keys


# Covers attributes block (56–71) with a negative "one-of" list case (line ~67)
def test_match_resource_attrs_one_of_negative():
    # r_attrs requires role to be one of {"admin", "editor"}, but resource has "viewer"
    rdef = {"attrs": {"role": ["admin", "editor"]}}
    resource = {"attrs": {"role": "viewer"}}
    assert (
        match_resource(rdef, resource) is False
    )  # hits the "one-of" negative branch (return False)


# Covers attributes block with a scalar mismatch branch (else -> str(rv) != str(v) -> return False)
def test_match_resource_attrs_scalar_mismatch_negative():
    # r_attrs requires level == "high", but resource has "low"
    rdef = {"attrs": {"level": "high"}}
    resource = {"attrs": {"level": "low"}}
    assert match_resource(rdef, resource) is False  # exercises the scalar inequality path


def test_match_resource_attrs_non_dict_is_ignored_returns_true():
    # r_attrs is not a dict -> attributes block is skipped entirely, returns True.
    rdef = {"attrs": "not-a-dict"}
    resource = {"attrs": {"any": "thing"}}
    assert match_resource(rdef, resource) is True


def test_match_resource_attrs_mixed_list_and_scalar_positive():
    # Mixed attributes: one list 'one-of' that matches, and one scalar that matches via string coercion.
    rdef = {"attrs": {"role": ["admin", "editor"], "level": "5"}}
    resource = {"attrs": {"role": "editor", "level": 5}}
    assert match_resource(rdef, resource) is True
