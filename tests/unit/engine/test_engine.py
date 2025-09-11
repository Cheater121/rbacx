
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

def test_basic_permit_and_mfa():
    policy = {
        "algorithm":"deny-overrides",
        "rules":[
            {"id":"r","effect":"permit","actions":["read"],"resource":{"type":"doc"}},
            {"id":"t","effect":"permit","actions":["transfer"],"resource":{"type":"payment"}, "obligations":[{"type":"require_mfa"}]}
        ]
    }
    g = Guard(policy)
    assert g.is_allowed_sync(Subject(id="u"), Action("read"), Resource(type="doc", id="1"), Context()) is True
    assert g.is_allowed_sync(Subject(id="u"), Action("transfer"), Resource(type="payment", id="1"), Context(attrs={"mfa": False})) is False
    assert g.is_allowed_sync(Subject(id="u"), Action("transfer"), Resource(type="payment", id="1"), Context(attrs={"mfa": True})) is True
