from types import SimpleNamespace


class XUserDemoAuthMiddleware:
    """
    Demo-only: map 'X-User' header to request.user.id if the user is anonymous.
    Enough for the RBAC demo decorator that only needs 'id'.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            uid = request.headers.get("x-user") or request.META.get("HTTP_X_USER")
        except Exception:
            uid = None

        # If user is anonymous, inject a minimal user object with an id.
        user = getattr(request, "user", None)
        if not getattr(user, "is_authenticated", False) and uid:
            request.user = SimpleNamespace(id=uid, is_authenticated=True, username=str(uid))

        return self.get_response(request)
