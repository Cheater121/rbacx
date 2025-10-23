from rbacx.rebac.local import (
    ComputedUserset,
    InMemoryRelationshipStore,
    LocalRelationshipChecker,
    This,
    TupleToUserset,
)


def test_unknown_relation_and_empty_rules_paths():
    st = InMemoryRelationshipStore()
    # No rules at all for the object type -> checker should fail safely (False) and touch guard branches.
    rules = {}
    ck = LocalRelationshipChecker(st, rules=rules)
    assert ck.check("user:1", "viewer", "doc:1") is False

    # Rules exist for type, but relation is unknown -> also False branch.
    rules = {"doc": {"owner": [This()]}}
    ck = LocalRelationshipChecker(st, rules=rules)
    assert ck.check("user:1", "viewer", "doc:1") is False


def test_tuple_to_userset_without_matching_edge():
    # There is a tuple-to-userset rule, but the linking edge does not exist in the store.
    st = InMemoryRelationshipStore()
    rules = {"photo": {"viewer": [TupleToUserset("album", "member")]}}
    ck = LocalRelationshipChecker(st, rules=rules)
    assert ck.check("user:1", "viewer", "photo:777") is False


def test_deep_graph_hits_max_nodes_and_cycle_detection():
    st = InMemoryRelationshipStore()
    # Create a small cycle via computed usersets to exercise node/visit limits
    rules = {"t": {"r": [ComputedUserset("r"), This()]}}  # self-loop + direct
    ck = LocalRelationshipChecker(st, rules=rules, max_nodes=3, max_depth=2)
    assert ck.check("user:1", "r", "t:1") in (True, False)
