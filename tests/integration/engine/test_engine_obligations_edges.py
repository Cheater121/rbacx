from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject


def env():
    return Subject(id="u"), Action(name="read"), Resource(type="doc")


def test_engine_obligation_blocks_then_allows():
    s, a, r = env()
    policy = {
        "rules": [
            {
                "id": "p",
                "actions": ["read"],
                "effect": "permit",
                "resource": {"type": "doc"},
                "obligations": [{"type": "require_mfa"}],
            }
        ]
    }
    g = Guard(policy=policy)
    d1 = g.evaluate_sync(s, a, r, context=Context(attrs={"mfa": False}))
    assert d1.allowed is False and d1.effect == "deny" and d1.challenge == "mfa"
    d2 = g.evaluate_sync(s, a, r, context=Context(attrs={"mfa": True}))
    assert d2.allowed is True and d2.effect == "permit"
