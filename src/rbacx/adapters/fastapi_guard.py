
from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

from ..core.engine import Guard
from ..core.model import Action, Context, Resource, Subject

EnvBuilder = Callable[[Any], Tuple[Subject, Action, Resource, Context]]

def make_guard_dependency(guard: Guard, context_getter: Optional[Callable[[Any], Dict[str, Any]]] = None) -> Callable[[Any], None]:
    """Factory to build a dependency without calling third-party helpers in defaults (B008-safe)."""
    def dep(request: Any) -> None:
        ctx_map: Dict[str, Any] = context_getter(request) if context_getter else {}
        _ctx = Context(attrs=ctx_map)
        # Example use: ensure allowed, otherwise raise inside endpoint
        # Left as no-op dependency (it can attach ctx to request if needed).
        return None
    return dep
