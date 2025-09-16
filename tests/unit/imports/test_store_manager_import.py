import importlib

import pytest


def test_store_manager_removed():
    with pytest.raises((ImportError, ModuleNotFoundError)):
        importlib.import_module("rbacx.store.manager")


def test_policy_loader_has_hotreloader():
    mod = importlib.import_module("rbacx.policy.loader")
    assert hasattr(mod, "HotReloader")
