import logging

from rbacx.rebac.local import (
    ComputedUserset,
    InMemoryRelationshipStore,
    LocalRelationshipChecker,
    TupleToUserset,
    _split_ref,
)


def test_split_ref_defaults_to_user_type():
    assert _split_ref("alice") == ("user", "alice")


def test_visits_exceeds_max_nodes_returns_false():
    st = InMemoryRelationshipStore()
    rules = {}
    ck = LocalRelationshipChecker(st, rules=rules, max_nodes=0)
    assert ck.check("user:1", "viewer", "doc:1") is False


def test_depth_exceeds_max_depth_continues_then_ends_false():
    st = InMemoryRelationshipStore()
    rules = {"doc": {"r": ComputedUserset("r")}}
    ck = LocalRelationshipChecker(st, rules=rules, max_depth=0)
    assert ck.check("user:1", "r", "doc:1") is False


def test_deadline_exceeded_returns_false():
    st = InMemoryRelationshipStore()
    rules = {}
    ck = LocalRelationshipChecker(st, rules=rules, deadline_ms=0)
    assert ck.check("user:1", "any", "doc:1") is False


def test_direct_allowed_unknown_caveat_treated_false():
    st = InMemoryRelationshipStore()
    st.add("user:1", "viewer", "doc:1", caveat="unknown")
    ck = LocalRelationshipChecker(st, rules={}, caveat_registry={})
    assert ck.check("user:1", "viewer", "doc:1") is False


def test_direct_allowed_caveat_predicate_raises_is_handled_and_warned(caplog):
    st = InMemoryRelationshipStore()

    def bad_pred(ctx):
        raise RuntimeError("boom")

    st.add("user:1", "viewer", "doc:1", caveat="c1")
    ck = LocalRelationshipChecker(st, rules={}, caveat_registry={"c1": bad_pred})
    with caplog.at_level(logging.WARNING, logger="rbacx.rebac.local"):
        assert ck.check("user:1", "viewer", "doc:1") is False
        assert any("ReBAC caveat 'c1' failed" in rec.getMessage() for rec in caplog.records)


def test_tuple_to_userset_ignores_edges_without_type_colon():
    st = InMemoryRelationshipStore()
    st.add("folder10", "parent", "doc:3")  # malformed object ref (no type:id)
    rules = {"doc": {"viewer": TupleToUserset(tupleset="parent", computed_userset="member")}}
    ck = LocalRelationshipChecker(st, rules=rules)
    st.add("user:7", "member", "folder10")
    assert ck.check("user:7", "viewer", "doc:3") is False


def test_unknown_expr_is_ignored_and_returns_false():
    st = InMemoryRelationshipStore()

    class UnknownExpr:
        pass

    rules = {"doc": {"v": UnknownExpr()}}
    ck = LocalRelationshipChecker(st, rules=rules)
    assert ck.check("user:1", "v", "doc:Z") is False


def test_depth_continue_line_144_hits_first_iteration():
    """
    Force the BFS to hit `if depth > self.max_depth: continue` (line 144) on the
    *first* loop iteration by setting max_depth = -1. That makes depth=0 > -1 True,
    so the 'continue' executes immediately and the queue drains with no expansions.
    """
    st = InMemoryRelationshipStore()
    # No rewrite rules and no direct tuples; we only want to exercise depth-gate.
    ck = LocalRelationshipChecker(
        st,
        rules={},  # no expansions
        max_depth=-1,  # depth=0 > -1 -> hits the `continue` at line 144
        max_nodes=999999,  # avoid max_nodes short-circuit
        deadline_ms=10_000,  # avoid deadline short-circuit
    )

    # Because we `continue` before any direct-check or expansion, the queue empties and returns False.
    assert ck.check("user:1", "any", "doc:1") is False
