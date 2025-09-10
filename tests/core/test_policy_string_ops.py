from rbacx.core import policy

def test_startswith_and_endswith_operators():
    env = {"s":"abcdef"}
    # DSL uses camelCase operators (startsWith/endsWith)
    assert policy.eval_condition({"startsWith":[{"attr":"s"}, "abc"]}, env) is True
    assert policy.eval_condition({"endsWith":[{"attr":"s"}, "def"]}, env) is True
    assert policy.eval_condition({"startsWith":[{"attr":"s"}, "zzz"]}, env) is False
    assert policy.eval_condition({"endsWith":[{"attr":"s"}, "zzz"]}, env) is False
