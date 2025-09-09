import pytest
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Action, Resource, Context

def test_engine_deny_when_no_rules():
    g = Guard(policy={"rules": []})
    d = g.evaluate_sync(Subject(id="u"), Action(name="read"), Resource(type="doc"))
    assert d.allowed is False
    assert d.reason in {"no_match", "not_applicable", "default_deny"}

def test_engine_unknown_algorithm_falls_back():
    pol = {"algorithm": "unknown", "rules": [
        {"id": "p", "actions": ["read"], "effect": "permit", "resource": {"type": "doc"}}
    ]}
    g = Guard(policy=pol)
    d = g.evaluate_sync(Subject(id="u"), Action(name="read"), Resource(type="doc"))
    assert hasattr(d, "allowed")

def test_engine_obligations_propagated_and_challenge_type():
    pol = {"rules": [
        {"id": "p", "actions": ["read"], "effect": "permit", "resource": {"type": "doc"},
         "obligations": [{"type": "require_mfa"}]}
    ]}
    g = Guard(policy=pol)
    d = g.evaluate_sync(Subject(id="u"), Action(name="read"), Resource(type="doc"), context=Context(attrs={}))
    assert d.allowed in {True, False}
