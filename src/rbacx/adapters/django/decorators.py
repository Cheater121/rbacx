from __future__ import annotations

from functools import wraps

from django.http import HttpRequest, HttpResponseForbidden  # type: ignore[import-untyped]

from ...core.model import Action, Context, Resource, Subject


def require(action: str, resource_type: str, *, audit: bool = False):
    def deco(view_func):
        @wraps(view_func)
        def _wrapped(request: HttpRequest, *args, **kwargs):
            guard = getattr(request, "rbacx_guard", None)
            if guard is None:
                return view_func(request, *args, **kwargs)
            sub = Subject(id=str(getattr(getattr(request, 'user', None), 'id', 'anonymous')))
            res = Resource(type=resource_type)
            ctx = Context(attrs={})
            ok = guard.is_allowed_sync(sub, Action(action), res, ctx)
            if not ok and not audit:
                return HttpResponseForbidden("Forbidden")
            return view_func(request, *args, **kwargs)
        return _wrapped
    return deco
