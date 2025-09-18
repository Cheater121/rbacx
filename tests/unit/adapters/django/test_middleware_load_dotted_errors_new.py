import sys
import types

import pytest

from rbacx.adapters.django.middleware import _load_dotted


def test_load_dotted_invalid_path_raises():
    with pytest.raises(ImportError):
        _load_dotted("notadottedpath")


def test_load_dotted_attr_missing_raises(monkeypatch):
    mod = types.ModuleType("tmpmod1")
    sys.modules["tmpmod1"] = mod
    with pytest.raises(ImportError):
        _load_dotted("tmpmod1.nope")


def test_load_dotted_not_callable_raises(monkeypatch):
    mod = types.ModuleType("tmpmod2")
    mod.factory = 123  # not callable
    sys.modules["tmpmod2"] = mod
    with pytest.raises(TypeError):
        _load_dotted("tmpmod2.factory")
