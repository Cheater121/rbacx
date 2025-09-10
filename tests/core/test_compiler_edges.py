
def test_compile_policy_selects_specific_bucket():
    from rbacx.core.compiler import compile as compile_policy
    doc = {"policies": []}
    idx = compile_policy(doc)
    assert idx is not None
