"""Demo-only middleware: reads X-Role header and attaches a fake subject."""

import asyncio


class XRoleDemoMiddleware:
    """Reads ``X-Role`` request header and stores it on the request.

    In a real app this would be replaced by Django's authentication
    middleware.  Here we just expose the header so ``build_env`` in
    views.py can construct a ``Subject`` with the requested role.
    """

    async_capable = True
    sync_capable = False

    def __init__(self, get_response):
        self.get_response = get_response
        if asyncio.iscoroutinefunction(self.get_response):
            self._is_coroutine = asyncio.coroutines._is_coroutine  # type: ignore[attr-defined]

    async def __call__(self, request):
        role = (
            getattr(request, "headers", {}).get("X-Role")
            or request.META.get("HTTP_X_ROLE")
            or "viewer"
        )
        request.demo_role = role
        return await self.get_response(request)
