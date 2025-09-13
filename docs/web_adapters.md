# Web framework adapters

RBACX ships simple adapters for popular frameworks.

## FastAPI (dependency)

```python
from fastapi import FastAPI, Depends, Request
from rbacx.adapters.fastapi import require_access
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

policy = {"algorithm": "deny-overrides", "rules": [
    {"id": "doc_read", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}
]}
guard = Guard(policy)

def build_env(request: Request):
    user_id = request.headers.get("x-user", "anonymous")
    return Subject(id=user_id, roles=["user"]), Action("read"), Resource(type="doc"), Context()

app = FastAPI()

@app.get("/doc", dependencies=[Depends(require_access(guard, build_env, add_headers=True))])
async def doc():
    return {"ok": True}
```

---

## Starlette (decorator)

```python
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from rbacx.adapters.starlette import require_access
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

policy = {"algorithm": "deny-overrides", "rules": [
    {"id": "doc_read", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}
]}
guard = Guard(policy)

def build_env(request: Request):
    user_id = request.headers.get("x-user", "anonymous")
    return Subject(id=user_id, roles=["user"]), Action("read"), Resource(type="doc"), Context()

app = Starlette()

@app.route("/docs")
@require_access(guard, build_env, add_headers=True)
async def docs(request: Request):
    return JSONResponse({"ok": True})
```

---

## Flask (decorator)

```python
from flask import Flask, jsonify
from rbacx.adapters.flask import require_access
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

policy = {"algorithm": "deny-overrides", "rules": [
    {"id": "doc_read", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}
]}
guard = Guard(policy)

def build_env(req):
    user_id = req.headers.get("x-user", "anonymous")
    return Subject(id=user_id, roles=["user"]), Action("read"), Resource(type="doc"), Context()

app = Flask(__name__)

@app.route("/docs")
@require_access(guard, build_env, add_headers=True)
def docs():
    return jsonify({"ok": True})
```

---

## Django REST Framework (permission class)

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from rbacx.adapters.drf import make_permission
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

policy = {"algorithm": "deny-overrides", "rules": [
    {"id": "doc_read", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}
]}
guard = Guard(policy)

def build_env(request):
    user_id = getattr(request.user, "username", "anonymous")
    return Subject(id=user_id, roles=["user"]), Action("read"), Resource(type="doc"), Context()

RBACXPermission = make_permission(guard, build_env)

class MyView(APIView):
    permission_classes = [RBACXPermission]

    def get(self, request, *args, **kwargs):
        return Response({"ok": True})
```
