import importlib
import pytest

litestar = pytest.importorskip("litestar", reason="Optional dep: Litestar not installed")
m = importlib.import_module("rbacx.adapters.litestar_guard")
assert hasattr(m, "require_access"), "litestar_guard must expose 'require_access'"
