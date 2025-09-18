# Guarded import to support differing Litestar versions.
try:
    from litestar.exceptions import ClientException  # type: ignore
except Exception:  # pragma: no cover - fallback if symbol not available

    class ClientException(Exception):
        """Fallback stub used when litestar.exceptions.ClientException is unavailable."""

        pass


import pytest

litestar = pytest.importorskip(
    "litestar", exc_type=ImportError, reason="Optional dep: skip on ImportError"
)
from rbacx.adapters.litestar_guard import require


class DummyConn:
    pass


class FakeGuardNoSync:
    # No is_allowed_sync -> use evaluate_sync branch
    def __init__(self, allowed: bool):
        self.allowed = allowed

    def evaluate_sync(self, sub, act, res, ctx):
        class D:
            allowed = self.allowed

        return D()


def test_litestar_guard_uses_evaluate_sync_when_no_is_allowed_sync():
    checker = require("read", "doc", audit=False)
    guard = FakeGuardNoSync(allowed=False)
    from litestar.exceptions import PermissionDeniedException

    with pytest.raises(PermissionDeniedException):
        checker(DummyConn(), guard)
