
import pytest
from rbacx.core.model import Subject, Resource, Action, Context
from dataclasses import FrozenInstanceError

def test_subject_defaults_and_immutability():
    s = Subject(id="u1")
    assert s.id == "u1"
    assert s.roles == []
    assert s.attrs == {}
    with pytest.raises(FrozenInstanceError):
        s.id = "u2"  # type: ignore

def test_resource_defaults_and_immutability():
    r = Resource(type="doc")
    assert r.type == "doc"
    assert r.id is None
    assert r.attrs == {}
    with pytest.raises(FrozenInstanceError):
        r.type = "file"  # type: ignore

def test_action_context_defaults():
    a = Action(name="read")
    c = Context()
    assert a.name == "read"
    assert c.attrs == {}
