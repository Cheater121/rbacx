from __future__ import annotations

import logging
from importlib import import_module
from typing import Any, Callable, Optional

# Optional Django imports to keep the module importable without Django installed
try:  # pragma: no cover
    from django.conf import settings  # type: ignore
except Exception:  # pragma: no cover
    settings = None  # type: ignore

logger = logging.getLogger("rbacx.adapters.django")


def _load_dotted(path: str) -> Callable[[], Any]:
    """Load a callable from a dotted path; prefer Django's import_string when available."""
    try:
        from django.utils.module_loading import import_string  # type: ignore

        obj = import_string(path)
    except Exception as err:
        # Fallback to manual import with proper exception chaining.
        mod, _, attr = path.rpartition(".")
        if not mod:
            raise ImportError(f"Invalid dotted path: {path}") from err
        module = import_module(mod)
        try:
            obj = getattr(module, attr)
        except AttributeError as attr_err:
            raise ImportError(f"Attribute '{attr}' not found in module '{mod}'") from attr_err

    if not callable(obj):
        raise TypeError(f"Object at '{path}' is not callable")
    return obj  # type: ignore[return-value]


class RbacxDjangoMiddleware:
    """Inject a Guard instance onto each Django request as `request.rbacx_guard`.

    Config:
      - settings.RBACX_GUARD_FACTORY: dotted path to a zero-arg callable returning a Guard.

    Notes:
      - Middleware __init__(get_response) runs once at startup; guard is created once.
      - __call__(request) runs per-request; we attach the same guard to each request.
    """

    def __init__(self, get_response: Callable) -> None:
        if settings is None:  # pragma: no cover
            raise RuntimeError("Django is required to use RbacxDjangoMiddleware")
        self.get_response = get_response
        self._guard: Optional[Any] = None

        factory_path = getattr(settings, "RBACX_GUARD_FACTORY", None)
        if factory_path:
            factory = _load_dotted(factory_path)
            self._guard = factory()

    def __call__(self, request):
        # Attach the guard to the request for downstream consumers
        if self._guard is not None:
            request.rbacx_guard = self._guard
        return self.get_response(request)
