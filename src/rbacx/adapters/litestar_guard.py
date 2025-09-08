from __future__ import annotations

from typing import Callable, Protocol, runtime_checkable

from litestar.connection import ASGIConnection

from ..core.engine import Guard
from ..core.model import Action, Context, Resource, Subject


@runtime_checkable
class _HasIsAllowedSync(Protocol):
    def is_allowed_sync(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context | None = None,
    ) -> bool: ...


def require(action: str, resource_type: str, *, audit: bool = False) -> Callable[[ASGIConnection, Guard], None]:
    def _checker(conn: ASGIConnection, guard: Guard) -> None:
        sub = Subject(id="anonymous")
        res = Resource(type=resource_type)
        ctx = Context(attrs={})
        allowed: bool
        if isinstance(guard, _HasIsAllowedSync):
            allowed = guard.is_allowed_sync(sub, Action(action), res, ctx)
        else:
            decision = guard.evaluate_sync(sub, Action(action), res, ctx)
            allowed = decision.allowed
        if not allowed and not audit:
            from litestar.exceptions import PermissionDeniedException
            raise PermissionDeniedException("Forbidden")
    return _checker
