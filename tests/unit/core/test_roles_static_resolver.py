from rbacx.core.roles import StaticRoleResolver


def test_expand_roles_with_inheritance_and_duplicates():
    r = StaticRoleResolver({"manager": ["employee"], "employee": ["user"]})
    out = r.expand(["manager", "manager"])
    assert out == ["employee", "manager", "user"]


def test_expand_with_none_or_empty():
    r = StaticRoleResolver()
    assert r.expand([]) == []
    assert r.expand(None) == []
