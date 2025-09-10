
import types
import pytest
from rbacx.core import policy
from rbacx.core.policy import ConditionTypeError

def test_match_actions_and_resource_basic():
    rule = {"actions": ["read", "*"]}
    assert policy.match_actions(rule, "read")
    assert policy.match_actions(rule, "write")  # because '*'

    # resource type/id/attrs matching
    rdef = {"type": ["doc", "file"], "id": "1", "attrs": {"x": 1, "y": ["a","b"]}}
    res = {"type": "doc", "id": "1", "attrs": {"x": 1, "y": "b", "z": 3}}
    assert policy.match_resource(rdef, res)

    # wrong id
    res2 = {"type": "doc", "id": "2", "attrs": {"x": 1, "y": "b"}}
    assert not policy.match_resource(rdef, res2)

def test_resolve_attr_path_works_with_dicts_and_objects():
    env = {"a": {"b": {"c": 5}}, "obj": types.SimpleNamespace(x=types.SimpleNamespace(y=7))}
    assert policy.resolve({"attr": "a.b.c"}, env) == 5
    assert policy.resolve({"attr": "obj.x.y"}, env) == 7
    # passthrough non-dict tokens
    assert policy.resolve(10, env) == 10

def test_numeric_and_collection_guards():
    with pytest.raises(ConditionTypeError):
        policy._ensure_numeric_strict(True, 2)
    with pytest.raises(ConditionTypeError):
        policy._ensure_numeric_strict("5", 2)  # no string coercion

    # collection ok
    assert list(policy._as_collection([1,2])) == [1,2]
    with pytest.raises(ConditionTypeError):
        policy._as_collection(123)

def test_eval_condition_operators():
    env = {"x": 5, "y": "abc", "arr": [1,2,3]}
    assert policy.eval_condition({"==": [{"attr": "x"}, 5]}, env) is True
    assert policy.eval_condition({"!=": [{"attr": "x"}, 6]}, env) is True
    assert policy.eval_condition({">": [{"attr": "x"}, 2]}, env) is True
    assert policy.eval_condition({">=": [{"attr": "x"}, 5]}, env) is True
    assert policy.eval_condition({"<": [{"attr": "x"}, 10]}, env) is True
    assert policy.eval_condition({"<=": [{"attr": "x"}, 5]}, env) is True
    assert policy.eval_condition({"contains": [{"attr": "arr"}, 2]}, env) is True
    # Correct operator names in the DSL are camelCase
    assert policy.eval_condition({"startsWith": [{"attr": "y"}, "a"]}, env) is True
    assert policy.eval_condition({"endsWith": [{"attr": "y"}, "c"]}, env) is True

    # and/or/not
    assert policy.eval_condition({"and": [{"==": [1,1]}, {"==": [2,2]}]}, env) is True
    assert policy.eval_condition({"or": [{"==": [1,2]}, {"==": [2,2]}]}, env) is True
    assert policy.eval_condition({"not": {"==": [1,2]}}, env) is True

def test_eval_condition_type_errors():
    env = {"x": "not-a-number"}
    with pytest.raises(ConditionTypeError):
        policy.eval_condition({">": [{"attr": "x"}, 2]}, env)
    with pytest.raises(ConditionTypeError):
        policy.eval_condition({"in": [1, 2]}, {})  # rhs must be iterable
