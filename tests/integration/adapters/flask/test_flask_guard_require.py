import pytest

pytest.importorskip("flask", reason="Optional dep: Flask not installed")

# Legacy flask_guard shim is no longer part of the public API; test is skipped by design.
pytest.skip("flask_guard legacy shim removed; skip", allow_module_level=True)
