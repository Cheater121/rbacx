import time

from rbacx.rebac.local import (
    ComputedUserset,
    InMemoryRelationshipStore,
    LocalRelationshipChecker,
    This,
    TupleToUserset,
)


def build_rules():
    return {
        "document": {
            "viewer": [This(), TupleToUserset("parent", "member")],
            "editor": [This(), ComputedUserset("owner")],
            "owner": [This()],
        },
        "folder": {
            "member": [This()],
        },
    }


def test_store_add_and_indexes():
    st = InMemoryRelationshipStore()
    st.add("user:1", "owner", "document:42")
    st.add("folder:10", "parent", "document:42")
    assert list(st.direct_for_resource("owner", "document:42"))[0].subject == "user:1"
    assert list(st.by_subject("folder:10", "parent"))[0].resource == "document:42"


def test_direct_and_computed_and_tuple_to_userset():
    st = InMemoryRelationshipStore()
    rules = build_rules()
    st.add("user:1", "viewer", "document:1")
    st.add("user:2", "owner", "document:2")
    st.add("folder:10", "parent", "document:3")
    st.add("user:3", "member", "folder:10")

    ck = LocalRelationshipChecker(st, rules=rules)
    assert ck.check("user:1", "viewer", "document:1") is True
    assert ck.check("user:2", "editor", "document:2") is True
    assert ck.check("user:3", "viewer", "document:3") is True
    assert ck.check("user:1", "editor", "document:1") is False
    assert ck.check("user:9", "viewer", "document:1") is False


def test_batch_check_uses_memo_and_keeps_length():
    st = InMemoryRelationshipStore()
    rules = build_rules()
    st.add("user:a", "viewer", "document:x")
    st.add("user:b", "viewer", "document:x")
    ck = LocalRelationshipChecker(st, rules=rules)
    triples = [
        ("user:a", "viewer", "document:x"),
        ("user:b", "viewer", "document:x"),
        ("user:a", "viewer", "document:x"),
    ]
    out = ck.batch_check(triples)
    assert out == [True, True, True]


def test_caveat_true_allows_and_false_denies():
    st = InMemoryRelationshipStore()
    rules = {"doc": {"viewer": [This()]}}
    st.add("user:7", "viewer", "doc:Z", caveat="is_weekend")
    st.add("user:8", "viewer", "doc:Z", caveat="is_weekend")

    registry = {"is_weekend": lambda ctx: bool(ctx and ctx.get("ok"))}
    ck = LocalRelationshipChecker(st, rules=rules, caveat_registry=registry)

    assert ck.check("user:7", "viewer", "doc:Z", context={"ok": True}) is True
    assert ck.check("user:8", "viewer", "doc:Z", context={"ok": False}) is False


def test_limits_max_depth_max_nodes_and_deadline():
    st = InMemoryRelationshipStore()
    rules = {"x": {"rel": [ComputedUserset("rel")]}}
    ck = LocalRelationshipChecker(st, rules=rules, max_depth=1, max_nodes=2, deadline_ms=1)

    assert ck.check("user:1", "rel", "x:obj") is False

    class SlowStore(InMemoryRelationshipStore):
        def direct_for_resource(self, relation, resource):
            time.sleep(0.003)
            return ()

    slow = SlowStore()
    ck2 = LocalRelationshipChecker(slow, rules=rules, deadline_ms=1)
    assert ck2.check("u:1", "rel", "x:1") is False
