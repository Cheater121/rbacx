from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject


def test_permit_overrides_any_permit_wins_cross_bucket() -> None:
    """Under permit-overrides a type-level permit overrides an id-specific deny.

    Previously this test asserted ``allowed is False`` (deny), which was an
    artifact of the broken single-bucket optimisation: the compiled path was
    picking only bucket 0 (id-specific) and discarding the type-level permit
    in bucket 2.  The correct semantics of permit-overrides are that *any*
    matching permit in the full rule set wins, regardless of how specifically
    the resource is described.

    Fixed in v1.9.3.
    """
    pol = {
        "algorithm": "permit-overrides",
        "rules": [
            # type-level permit (bucket 2): matches any doc
            {"id": "wild", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
            # id-specific deny (bucket 0): matches only doc id=A
            {
                "id": "specific",
                "effect": "deny",
                "actions": ["read"],
                "resource": {"type": "doc", "id": "A"},
            },
        ],
    }
    d = Guard(pol).evaluate_sync(
        Subject(id="u"), Action("read"), Resource(type="doc", id="A"), Context()
    )
    # permit-overrides: the type-level permit must win over the id-specific deny.
    assert d.allowed is True and d.rule_id == "wild"
