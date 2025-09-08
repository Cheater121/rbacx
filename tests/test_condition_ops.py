
from rbacx.core.policy import eval_condition

def test_ops_eq_ne_gt_lt_ge_le_contains_prefix_suffix():
    env = {"subject": {"id":"u"}, "action": "read", "resource": {"type":"doc","attrs":{"n": 5, "s":"hello"}}, "context": {}}
    assert eval_condition({"==":[1,1]}, env) is True
    assert eval_condition({"!=":[1,2]}, env) is True
    assert eval_condition({">":[{"attr":"resource.attrs.n"}, 3]}, env) is True
    assert eval_condition({">=":[{"attr":"resource.attrs.n"}, 5]}, env) is True
    assert eval_condition({"<":[{"attr":"resource.attrs.n"}, 10]}, env) is True
    assert eval_condition({"<=":[{"attr":"resource.attrs.n"}, 5]}, env) is True
    assert eval_condition({"contains":[[1,2,3], 2]}, env) is True
    assert eval_condition({"startsWith":[{"attr":"resource.attrs.s"}, "he"]}, env) is True
    assert eval_condition({"endsWith":[{"attr":"resource.attrs.s"}, "lo"]}, env) is True
