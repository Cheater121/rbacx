import importlib


def test_static_role_resolver_expand_transitive():
    roles_mod = importlib.import_module("rbacx.core.roles")
    # Ensure StaticRoleResolver exists
    Resolver = roles_mod.StaticRoleResolver
    graph = {
        "manager": ["employee"],
        "employee": ["user"],
        "user": [],
        "guest": [],
    }
    r = Resolver(graph)
    # 'manager' should expand transitively to include parents
    assert r.expand(["manager"]) == ["employee", "manager", "user"]
    # Duplicates and cycles should be handled gracefully
    graph_cycle = {"a": ["b"], "b": ["a"]}
    r2 = Resolver(graph_cycle)
    assert r2.expand(["a"]) == ["a", "b"]
    # Empty input yields empty list
    assert r.expand([]) == []
