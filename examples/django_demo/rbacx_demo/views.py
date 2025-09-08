
from django.http import JsonResponse
from rbacx.core.model import Subject, Resource, Action, Context

def index(request):
    g = getattr(request, "rbacx_guard", None)
    ok = False
    if g:
        ok = g.is_allowed_sync(Subject(id="u1"), Action("read"), Resource(type="doc"), Context())
    return JsonResponse({"allowed": ok})


def health(request):
    return JsonResponse({"ok": True})
