"""Async views for the RBACX async Django demo.

All views are ``async def`` and use ``async_require_access`` from
``rbacx.adapters.django.decorators``.

Endpoints
---------
GET /health        — always OK (no auth check)
GET /doc           — requires role "admin" or "editor" (via roles shorthand)
GET /doc/admin     — requires role "admin" only
"""

from __future__ import annotations

from django.http import JsonResponse

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.adapters.django.decorators import async_require_access

# Separate stricter Guard for admin-only endpoints.
# Uses a dedicated policy that only permits the "admin" role.
_ADMIN_ONLY_GUARD = Guard(
    {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "permit-read-doc-admin-only",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
            }
        ],
    }
)


def _build_env(request):
    """Extract subject / action / resource / context from the request.

    In this demo the role comes from the ``X-Role`` header (set by
    ``XRoleDemoMiddleware``).  In production replace with real auth.
    """
    role = getattr(request, "demo_role", "viewer")
    subject = Subject(id="demo-user", roles=[role])
    action = Action("read")
    resource = Resource(type="doc", id="demo-doc-1")
    return subject, action, resource, Context()


async def health(request):
    """Health check — no access control required."""
    return JsonResponse({"ok": True})


@async_require_access(_build_env, add_headers=True)
async def doc(request):
    """Read a document — allowed for 'admin' and 'editor' roles.

    Uses the ``roles`` shorthand in policy.json instead of a verbose
    ``hasAny`` condition.

    Try:
        curl http://127.0.0.1:8005/doc                        → 403
        curl -H "X-Role: editor" http://127.0.0.1:8005/doc   → 200
        curl -H "X-Role: admin"  http://127.0.0.1:8005/doc   → 200
    """
    return JsonResponse({"allowed": True, "docs": ["doc-1", "doc-2"]})


@async_require_access(_build_env, guard=_ADMIN_ONLY_GUARD, add_headers=True)
async def doc_admin(request):
    """Admin-only document endpoint — uses a dedicated stricter Guard.

    The explicit ``guard=_ADMIN_ONLY_GUARD`` overrides ``request.rbacx_guard``
    injected by the middleware, demonstrating how to apply a tighter policy
    for specific endpoints without changing the global Guard.

    Try:
        curl http://127.0.0.1:8005/doc/admin                       → 403
        curl -H "X-Role: editor" http://127.0.0.1:8005/doc/admin   → 403
        curl -H "X-Role: admin"  http://127.0.0.1:8005/doc/admin   → 200
    """
    return JsonResponse({"allowed": True, "admin_data": "top-secret"})
