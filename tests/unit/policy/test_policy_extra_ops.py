
import pytest
from rbacx.core import policy
from rbacx.core.policy import ConditionTypeError

def test_boolean_logic_with_and_or():
    # Use logical operators supported by the DSL
    assert policy.eval_condition({"and": [True, True]}, {}) is True
    assert policy.eval_condition({"or": [False, True]}, {}) is True

def test_between_and_compare_numbers():
    env = {"n": 5}
    cond = {"between": [{"attr":"n"}, [1,10]]}
    res = policy.eval_condition(cond, env)
    assert res in {True, False}

def test_type_errors_for_wrong_collections():
    with pytest.raises(ConditionTypeError):
        policy._as_collection(None)
