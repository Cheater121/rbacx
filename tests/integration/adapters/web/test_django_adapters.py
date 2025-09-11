import pytest

# Requires Django; if it's missing, gracefully skip the entire module
django = pytest.importorskip("django")
from django.conf import settings

# Minimal Django configuration for DRF tests
if not settings.configured:
    settings.configure(
        SECRET_KEY="test-secret",
        DEBUG=True,
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["testserver", "localhost"],
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "rest_framework",
        ],
        MIDDLEWARE=[],
    )
    import django as _dj

    _dj.setup()

# Now it's safe to work with DRF
pytest.importorskip("rest_framework")
from rest_framework.test import APIRequestFactory  # noqa: E402

from dataclasses import dataclass

from rbacx.adapters.drf import make_permission  # noqa: E402
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


def build_env(req):
    return Subject(id="u"), Action("read"), Resource(type="doc"), Context(attrs={})


def test_drf_permission_allow_and_message():
    rf = APIRequestFactory()
    req = rf.get("/x")

    PermAllow = make_permission(FakeGuard(True), build_env)
    p_ok = PermAllow()
    assert p_ok.has_permission(req, None) is True

    PermDeny = make_permission(FakeGuard(False, "nope"), build_env)
    p_ng = PermDeny()
    assert p_ng.has_permission(req, None) is False
    # DRF Permission.message must contain the reason
    assert "nope" in str(getattr(p_ng, "message", ""))

