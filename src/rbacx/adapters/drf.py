
from __future__ import annotations

from typing import Any, Callable

from rest_framework.permissions import BasePermission  # type: ignore

from ..core.engine import Guard
from ..core.model import Action, Context, Resource, Subject


def make_permission(guard: Guard, build_env: Callable[[Any], tuple[Subject, Action, Resource, Context]]):
    class RBACXPermission(BasePermission):
        message = "forbidden"
        def has_permission(self, request, view):
            subject, action, resource, context = build_env(request)
            dec = guard.evaluate_sync(subject, action, resource, context)
            self.message = f"forbidden: {dec.reason}"
            return bool(dec.allowed)
    return RBACXPermission
