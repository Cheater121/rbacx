from __future__ import annotations

from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_GET

from rbacx import Action, Context, Resource, Subject
from rbacx.adapters.django.decorators import require_access


def build_env(request):
    user = getattr(getattr(request, "user", None), "id", None) or "anonymous"
    return Subject(id=str(user), roles=["user"]), Action("read"), Resource(type="doc"), Context()


@require_GET
def index(request):
    return HttpResponse(
        "Django demo is alive. Visit /admin/ for the admin site.",
        content_type="text/plain",
    )


@require_GET
def health(request):
    return JsonResponse({"ok": True})


@require_access(build_env, add_headers=True)
@require_GET
def doc(request):
    return JsonResponse({"allowed": True, "docs": ["doc-1", "doc-2"]})
