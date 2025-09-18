# Ensure Litestar adapter can be imported and exposes expected API.
# We intentionally avoid importing the 'litestar' package directly here,
# because some environments raise ImportError during 'litestar' import even when installed,
# due to version/plugin mismatches. Importing the adapter module is sufficient for this unit test.
# Comments in English per project rules.
import pytest

lg = pytest.importorskip(
    "rbacx.adapters.litestar_guard",
    exc_type=ImportError,
    reason="Optional dep: Litestar adapter unavailable",
)


def test_litestar_guard_exports_require():
    assert hasattr(lg, "require"), "litestar_guard must expose 'require'"
