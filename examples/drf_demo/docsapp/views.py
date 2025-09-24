import json
import pathlib

from rest_framework.response import Response
from rest_framework.views import APIView

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.adapters.drf import make_permission

_policy_path = pathlib.Path(__file__).with_name("policy.json")
_guard = Guard(json.loads(_policy_path.read_text(encoding="utf-8")))


def build_env(request):
    user = getattr(request, "user", None)
    uid = getattr(user, "username", None) or "anonymous"
    return Subject(id=uid, roles=["user"]), Action("read"), Resource(type="doc"), Context()


RBACXPermission = make_permission(_guard, build_env)


class DocsView(APIView):
    permission_classes = [RBACXPermission]

    def get(self, request):
        return Response({"ok": True})
