from __future__ import annotations

try:
    from importlib.metadata import PackageNotFoundError, version  # py3.8+
except Exception:  # pragma: no cover
    version = None  # type: ignore
    PackageNotFoundError = Exception  # type: ignore

# Public, convenient imports
from .core.decision import Decision
from .core.engine import Guard
from .core.model import Action, Context, Resource, Subject
from .policy.loader import HotReloader, load_policy

__all__ = [
    "Guard",
    "Subject",
    "Action",
    "Resource",
    "Context",
    "Decision",
    "HotReloader",
    "load_policy",
    "core",
    "adapters",
    "storage",
    "obligations",
    "__version__",
]


def _detect_version() -> str:
    try:
        if version is None:
            raise PackageNotFoundError
        return version("rbacx")
    except Exception:
        return "0.1.0"


__version__ = _detect_version()
