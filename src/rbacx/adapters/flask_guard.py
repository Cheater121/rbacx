
from __future__ import annotations

from functools import wraps

from flask import abort, g  # type: ignore

from ..core.model import Action, Context, Resource, Subject


def require(action: str, resource_type: str, *, audit: bool = False):
    def deco(fn):
        @wraps(fn)
        def _wrapped(*args, **kwargs):
            guard = getattr(g, "rbacx_guard", None)
            if not guard:  # no guard -> allow
                return fn(*args, **kwargs)
            sub = Subject(id=getattr(getattr(g, 'user', None), 'id', 'anonymous'))
            res = Resource(type=resource_type)
            ctx = Context(attrs={})
            ok = guard.is_allowed_sync(sub, Action(action), res, ctx)
            if not ok and not audit:
                abort(403)
            return fn(*args, **kwargs)
        return _wrapped
    return deco
