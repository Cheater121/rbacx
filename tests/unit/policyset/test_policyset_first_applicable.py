
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

def test_policyset_first_applicable():
    ps = {
        "algorithm":"first-applicable",
        "policies":[
            {"rules":[{"id":"deny1","effect":"deny","actions":["read"],"resource":{"type":"doc","attrs":{"cls":"secret"}}}]},
            {"rules":[{"id":"permit1","effect":"permit","actions":["read"],"resource":{"type":"doc"}}]},
            {"rules":[{"id":"permit2","effect":"permit","actions":["read"],"resource":{"type":"doc"}}]},
        ]
    }
    g = Guard(ps)
    # resource without cls matches permit1 and stops; permit2 shouldn't be reached
    assert g.is_allowed_sync(Subject(id="u"), Action("read"), Resource(type="doc", attrs={}), Context()) is True
