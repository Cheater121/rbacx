# -*- coding: utf-8 -*-
import importlib
import importlib.util
import sys
import types
from dataclasses import dataclass

import pytest

# --- helpers -----------------------------------------------------------------


def _drf_installed() -> bool:
    return importlib.util.find_spec("rest_framework") is not None


def _django_installed() -> bool:
    return importlib.util.find_spec("django") is not None


class _unshadow_django:
    """
    Temporarily remove in-repo shims for django.http / django.conf from sys.modules
    so DRF can import the real Django (Http404, QueryDict, etc.). Restore after import.
    """

    def __enter__(self):
        self._saved = {}
        # If django.http is a shim (no Http404), temporarily remove it
        if "django.http" in sys.modules and not hasattr(sys.modules["django.http"], "Http404"):
            self._saved["django.http"] = sys.modules.pop("django.http")
        # If django.conf.settings is a SimpleNamespace, it's a shim — temporarily remove it
        if "django.conf" in sys.modules:
            mod = sys.modules["django.conf"]
            if isinstance(getattr(mod, "settings", None), types.SimpleNamespace):
                self._saved["django.conf"] = sys.modules.pop("django.conf")
        return self

    def __exit__(self, exc_type, exc, tb):
        # Restore original shims so other tests relying on them continue to work
        for name, mod in self._saved.items():
            sys.modules[name] = mod


def _import_make_permission():
    """
    Safely import DRF and then rbacx.adapters.drf:make_permission.
    If dependencies are missing, skip the whole module.
    """
    if not _drf_installed():
        pytest.skip("Django REST framework not installed; skipping", allow_module_level=True)
    if not _django_installed():
        pytest.skip("Django not installed; skipping", allow_module_level=True)

    with _unshadow_django():
        # Ensure DRF binds to the real django.http/django.conf
        importlib.import_module("rest_framework")
        # Now import the project's factory
        from rbacx.adapters.drf import make_permission  # noqa: WPS433
    return make_permission


# Gate the import at module import time (or skip)
make_permission = _import_make_permission()

# --- test subject imports -----------------------------------------------------

from rbacx.core.model import Action, Context, Resource, Subject  # noqa: E402


@dataclass
class Decision:
    allowed: bool
    reason: str | None = None


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
    return Subject(id="u"), Action("read"), Resource(type="doc"), Context(attrs={})


def test_drf_permission_allow_and_message():
    # A minimal request-like object is enough; Permission doesn't require real HttpRequest
    req = types.SimpleNamespace(path="/x", method="GET", META={}, headers={})

    PermAllow = make_permission(FakeGuard(True), build_env)
    p_ok = PermAllow()
    assert p_ok.has_permission(req, None) is True

    PermDeny = make_permission(FakeGuard(False, "nope"), build_env)
    p_ng = PermDeny()
    assert p_ng.has_permission(req, None) is False
    assert "nope" in str(getattr(p_ng, "message", ""))
