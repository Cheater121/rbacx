
import builtins
import importlib
import types
import pytest

import rbacx.__init__ as rmod

def test_version_detect_ok(monkeypatch):
    # simulate installed package
    class DummyExc(Exception): pass
    monkeypatch.setattr(rmod, "PackageNotFoundError", DummyExc, raising=False)
    calls = {}
    def fake_version(name):
        calls['name'] = name
        return "9.9.9"
    monkeypatch.setattr(rmod, "version", fake_version, raising=False)
    assert rmod._detect_version() == "9.9.9"
    assert calls['name'] == "rbacx"

def test_version_detect_fallback(monkeypatch):
    # simulate metadata missing
    class DummyExc(Exception): pass
    monkeypatch.setattr(rmod, "PackageNotFoundError", DummyExc, raising=False)
    monkeypatch.setattr(rmod, "version", None, raising=False)
    assert rmod._detect_version() == "0.1.0"

def test_version_detect_exception(monkeypatch):
    # simulate version raising
    class DummyExc(Exception): pass
    monkeypatch.setattr(rmod, "PackageNotFoundError", DummyExc, raising=False)
    def raising(name):
        raise DummyExc("nope")
    monkeypatch.setattr(rmod, "version", raising, raising=False)
    assert rmod._detect_version() == "0.1.0"
