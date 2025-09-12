# -*- coding: utf-8 -*-
import importlib
import importlib.util
import sys
import types
from dataclasses import dataclass

import pytest


def _drf_installed() -> bool:
    return importlib.util.find_spec("rest_framework") is not None


def _django_installed() -> bool:
    return importlib.util.find_spec("django") is not None


class _unshadow_django:
    """
    Temporarily remove in-repo shims for django.http / django.conf from sys.modules
    so DRF can import the real Django modules. Restore them afterwards.
    """

    def __enter__(self):
        self._saved = {}
        if "django.http" in sys.modules and not hasattr(sys.modules["django.http"], "Http404"):
            self._saved["django.http"] = sys.modules.pop("django.http")
        if "django.conf" in sys.modules:
            mod = sys.modules["django.conf"]
            if isinstance(getattr(mod, "settings", None), types.SimpleNamespace):
                self._saved["django.conf"] = sys.modules.pop("django.conf")
        return self

    def __exit__(self, exc_type, exc, tb):
        for name, mod in self._saved.items():
            sys.modules[name] = mod


def _import_make_permission():
    if not _drf_installed():
        pytest.skip("Django REST framework not installed; skipping", allow_module_level=True)
    if not _django_installed():
        pytest.skip("Django not installed; skipping", allow_module_level=True)
    with _unshadow_django():
        importlib.import_module("rest_framework")
        from rbacx.adapters.drf import make_permission  # noqa: WPS433
    return make_permission


make_permission = _import_make_permission()


@dataclass
class Decision:
    allowed: bool
    reason: str | None = None
    rule_id: str | None = None
    policy_id: str | None = None


class FakeGuard:
    def __init__(self, allowed: bool, reason: str | None = None):
        self._allowed = allowed
        self._reason = reason

    def is_allowed_sync(self, sub, act, res, ctx) -> bool:
        return self._allowed

    def evaluate_sync(self, sub, act, res, ctx) -> Decision:
        return Decision(self._allowed, self._reason)

    def explain_sync(self, sub, act, res, ctx) -> Decision:
        return Decision(self._allowed, self._reason)


def build_env(_req):
    from rbacx.core.model import Action, Context, Resource, Subject

    return Subject(id="u"), Action("read"), Resource(type="doc"), Context(attrs={})


def test_drf_permission_allow_and_message():
    # Minimal request-like object, no real Django request required
    req = types.SimpleNamespace(path="/x", method="GET", META={}, headers={})

    Perm = make_permission(FakeGuard(True), build_env)
    p = Perm()
    assert p.has_permission(req, None) is True

    Perm2 = make_permission(FakeGuard(False, "nope"), build_env)
    p2 = Perm2()
    assert p2.has_permission(req, None) is False
    assert "nope" in str(getattr(p2, "message", ""))
