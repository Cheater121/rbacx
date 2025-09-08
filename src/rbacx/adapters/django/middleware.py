from __future__ import annotations

import logging
from importlib import import_module
from typing import Any, Callable

from django.conf import settings  # type: ignore[import-untyped]

logger = logging.getLogger("rbacx.adapters.django")


def _load_dotted(path: str) -> Callable[[], Any]:
    mod, _, attr = path.rpartition(".")
    if not mod:
        raise ImportError(f"Invalid dotted path: {path}")
    m = import_module(mod)
    obj = getattr(m, attr, None)
    if obj is None:
        raise ImportError(f"Attribute '{attr}' not found in module '{mod}'")
    if not callable(obj):
        raise TypeError(f"Object at '{path}' is not callable")
    return obj


class RbacxDjangoMiddleware:
    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response
        self._guard: Any | None = None
        factory_path = getattr(settings, "RBACX_GUARD_FACTORY", None)
        if factory_path:
            factory = _load_dotted(factory_path)
            self._guard = factory()

    def __call__(self, request):
        if self._guard is not None:
            request.rbacx_guard = self._guard
        response = self.get_response(request)
        return response
