from __future__ import annotations

from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_GET

from rbacx.core.model import Action, Context, Resource, Subject


@require_GET
def index(request):
    return HttpResponse(
        "Django demo is alive. Visit /admin/ for the admin site.",
        content_type="text/plain",
    )


@require_GET
def health(request):
    return JsonResponse({"ok": True})


@require_GET
def doc(request):
    guard = getattr(request, "rbacx_guard", None)
    if guard is None:
        return JsonResponse({"error": "RBACX guard is not configured"}, status=500)

    user = request.headers.get("x-user", "anonymous")
    subject = Subject(id=user, roles=["user"])  # roles used by the demo policy
    action = Action("read")
    resource = Resource(type="doc")
    context = Context()

    decision = guard.evaluate_sync(subject, action, resource, context)

    if not decision.allowed:
        # If the engine returned reason/challenge, expose it to make the demo informative.
        payload = {"allowed": False, "reason": decision.reason or "forbidden"}
        return JsonResponse(payload, status=403)

    return JsonResponse({"allowed": True, "docs": ["doc-1", "doc-2"]})
