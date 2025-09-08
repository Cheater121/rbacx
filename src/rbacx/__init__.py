
from __future__ import annotations

try:
    from importlib.metadata import PackageNotFoundError, version  # py3.8+
except Exception:  # pragma: no cover
    version = None  # type: ignore
    PackageNotFoundError = Exception  # type: ignore

__all__ = ["core", "adapters", "storage", "obligations", "__version__"]

def _detect_version() -> str:
    try:
        if version is None:
            raise PackageNotFoundError  # type: ignore
        return version("rbacx")
    except Exception:
        return "0.1.0"

__version__ = _detect_version()
