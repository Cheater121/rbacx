from __future__ import annotations

from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_GET

from rbacx.adapters.django.decorators import require


@require_GET
def index(request):
    return HttpResponse(
        "Django demo is alive. Visit /admin/ for the admin site.",
        content_type="text/plain",
    )


@require_GET
def health(request):
    return JsonResponse({"ok": True})


@require("read", "doc", audit=False)
@require_GET
def doc(request):
    return JsonResponse({"allowed": True, "docs": ["doc-1", "doc-2"]})
