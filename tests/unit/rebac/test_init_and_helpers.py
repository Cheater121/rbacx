import importlib


def test_package_exports():
    mod = importlib.import_module("rbacx.rebac")
    expected = {
        "LocalRelationshipChecker",
        "InMemoryRelationshipStore",
        "UsersetExpr",
        "This",
        "ComputedUserset",
        "TupleToUserset",
    }
    assert set(mod.__all__) == expected


def test_standard_userset_variants():
    from rbacx.rebac.helpers import standard_userset
    from rbacx.rebac.local import ComputedUserset, This, TupleToUserset

    rules = standard_userset()
    assert list(rules["owner"])[0] == This()
    assert isinstance(rules["viewer"][1], ComputedUserset)
    assert rules["viewer"][1].relation == "editor"
    assert rules["editor"][1].relation == "owner"
    assert any(
        isinstance(x, TupleToUserset) and x.tupleset == "granted" and x.computed_userset == "member"
        for x in rules["viewer"]
    )

    rules2 = standard_userset(parent_rel="parent", with_group_grants=False)
    for rel in ("viewer", "editor", "owner"):
        assert any(
            isinstance(x, TupleToUserset) and x.tupleset == "parent" and x.computed_userset == rel
            for x in rules2[rel]
        )
    assert not any(
        isinstance(x, TupleToUserset) and x.tupleset == "granted" for x in rules2["viewer"]
    )
