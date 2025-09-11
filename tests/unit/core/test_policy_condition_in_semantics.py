
from rbacx.core import policy

def test_in_string_and_collection_semantics():
    env = {"s": "abcdef", "x": 3, "arr": [1,2,3,4]}
    assert policy.eval_condition({"in": ["bcd", {"attr":"s"}]}, env) is True
    assert policy.eval_condition({"in": [{"attr":"x"}, {"attr":"arr"}]}, env) is True
    assert policy.eval_condition({"in": [[2,3], {"attr":"arr"}]}, env) in {True, False}
