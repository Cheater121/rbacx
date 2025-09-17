from dataclasses import dataclass

from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_GET


@dataclass
class DemoSubject:
    id: str
    roles: list[str]


@require_GET
def index(request):
    return HttpResponse(
        "Django demo is alive. Visit /admin/ for the admin site.", content_type="text/plain"
    )


@require_GET
def health(request):
    return JsonResponse({"ok": True})


@require_GET
def doc(request):
    guard = getattr(request, "rbacx_guard", None)
    if guard is None:
        return JsonResponse(
            {"allowed": False, "reason": "guard is not attached by middleware"}, status=500
        )

    subject = DemoSubject(id="anonymous", roles=["demo_user"])
    decision = guard.evaluate_sync(subject, "read", "doc", context={})

    # Normalize decision
    allowed = False
    if isinstance(decision, dict):
        allowed = bool(decision.get("allowed", False))
        reason = decision.get("reason")
    else:
        allowed = bool(getattr(decision, "allowed", False))
        reason = getattr(decision, "reason", None)

    if not allowed:
        return JsonResponse({"allowed": False, "reason": reason or "forbidden"}, status=403)

    data = {"allowed": True, "docs": ["doc-1", "doc-2"]}
    if reason:
        data["reason"] = reason
    return JsonResponse(data)
