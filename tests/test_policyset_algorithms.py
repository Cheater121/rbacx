
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

def test_policyset_deny_overrides():
    ps = {
        "algorithm":"deny-overrides",
        "policies":[
            {"rules":[{"id":"deny","effect":"deny","actions":["read"],"resource":{"type":"doc"}}]},
            {"rules":[{"id":"permit","effect":"permit","actions":["read"],"resource":{"type":"doc"}}]},
        ]
    }
    g = Guard(ps)
    assert g.is_allowed_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context()) is False

def test_policyset_permit_overrides():
    ps = {
        "algorithm":"permit-overrides",
        "policies":[
            {"rules":[{"id":"deny","effect":"deny","actions":["read"],"resource":{"type":"doc","attrs":{"visibility":"private"}}}]},
            {"rules":[{"id":"permit","effect":"permit","actions":["read"],"resource":{"type":"doc"}}]},
        ]
    }
    g = Guard(ps)
    assert g.is_allowed_sync(Subject(id="u"), Action("read"), Resource(type="doc", attrs={"visibility":"public"}), Context()) is True
