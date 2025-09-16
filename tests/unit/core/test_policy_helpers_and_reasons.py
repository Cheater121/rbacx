import pytest

from rbacx.core.policy import (
    ConditionTypeError,
    eval_condition,
    evaluate,
    match_actions,
    match_resource,
)


def test_match_actions_basic_and_non_iterable():
    assert match_actions({"actions": ["read", "write"]}, "read") is True
    # non-iterable -> False
    assert match_actions({"actions": 123}, "read") is False
    # non-string items in list are ignored; still true if at least one string matches
    assert match_actions({"actions": ["read", 5, None]}, "read") is True
    assert match_actions({"actions": [5, None]}, "read") is False


def test_match_resource_type_id_and_attrs_list_one_of():
    res = {"type": "doc", "id": "1", "attrs": {"vis": "public", "tag": "x"}}
    # type mismatch
    assert match_resource({"type": "img"}, res) is False
    # id mismatch
    assert match_resource({"type": "doc", "id": "2"}, res) is False
    # attribute "one-of" semantics: when rule value is list — resource value must be among them
    assert match_resource({"type": "doc", "attrs": {"vis": ["internal", "public"]}}, res) is True
    # exact value mismatch on scalar
    assert match_resource({"type": "doc", "attrs": {"vis": "internal"}}, res) is False


def test_eval_condition_unknown_operator_and_as_collection_error():
    # unknown operator returns False
    assert eval_condition({"unknown": [1, 2]}, {}) is False
    # _as_collection rejects wrong types via ConditionTypeError (indirectly via 'in')
    with pytest.raises(ConditionTypeError):
        eval_condition({"in": [{"attr": "a"}, 123]}, {"a": 1})


def _env(action="read", res_id="1", attrs=None):
    return {
        "action": action,
        "resource": {"type": "doc", "id": res_id, "attrs": attrs or {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def test_evaluate_reason_paths_action_resource_and_condition():
    policy = {
        "rules": [
            {
                "id": "r1",
                "actions": ["write"],
                "resource": {"type": "doc"},
                "effect": "permit",
            },  # action_mismatch
            {
                "id": "r2",
                "actions": ["read"],
                "resource": {"type": "doc", "id": "X"},
                "effect": "permit",
            },  # resource_mismatch
            {
                "id": "r3",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "condition": {"==": [{"attr": "missing"}, 1]},
                "effect": "permit",
            },  # condition_mismatch
            {
                "id": "r4",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "condition": {"between": [{"attr": "bad"}, [1]]},
                "effect": "permit",
            },  # type error -> condition_type_mismatch
        ]
    }
    out = evaluate(policy, _env())
    assert out["decision"] == "deny"
    # one из этих reason должен сохраниться как наиболее информативный
    assert out["reason"] in {
        "action_mismatch",
        "resource_mismatch",
        "condition_mismatch",
        "condition_type_mismatch",
    }
