# Web framework adapters

RBACX ships simple adapters for popular frameworks. for popular Python web frameworks.
They all follow the same conventions:

- **EnvBuilder** builds `(Subject, Action, Resource, Context)` from the framework request/scope.
- **Async frameworks use async adapters** (`evaluate_async` under the hood).
- **Sync frameworks use sync adapters** (`evaluate_sync`).
- By default, **do not leak reasons**. If you need diagnostics, pass `add_headers=True` and read:
  - `X-RBACX-Reason`
  - `X-RBACX-Rule`
  - `X-RBACX-Policy`

See runnable apps in `examples/`.

---

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
    uid = request.headers.get("x-user", "anonymous")
    return Subject(id=uid, roles=["user"]), Action("read"), Resource(type="doc"), Context()

app = FastAPI()

@app.get("/doc", dependencies=[Depends(require_access(guard, build_env, add_headers=True))])
async def doc():
    return {"ok": True}
```

---

## Flask (decorator)

```python
from flask import Flask, request
from rbacx.adapters.flask import require_access
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

guard = Guard(policy)

def build_env(req):
    # use explicit req or implicit flask.request
    r = req or request
    uid = r.headers.get("x-user", "anonymous")
    return Subject(id=uid, roles=["user"]), Action("read"), Resource(type="doc"), Context()

app = Flask(__name__)

@app.get("/doc")
@require_access(guard, build_env, add_headers=True)
def doc():
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

guard = Guard(policy)

def build_env(request: Request):
    uid = request.headers.get("x-user", "anonymous")
    return Subject(id=uid, roles=["user"]), Action("read"), Resource(type="doc"), Context()

app = Starlette()

@app.route("/doc")
@require_access(guard, build_env, add_headers=True)
async def doc(request: Request):
    return JSONResponse({"ok": True})
```

---

## Litestar (middleware)

```python
from litestar import Litestar, get
from litestar.middleware import DefineMiddleware
from rbacx.adapters.litestar import RBACXMiddleware
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

guard = Guard(policy)

def build_env(scope):
    uid = dict(scope.get("headers", [])).get(b"x-user", b"anonymous").decode("latin1")
    return Subject(id=uid, roles=["user"]), Action("read"), Resource(type="doc"), Context()

@get("/doc")
async def doc() -> dict:
    return {"ok": True}

app = Litestar(
    route_handlers=[doc],
    middleware=[DefineMiddleware(RBACXMiddleware, guard=guard, build_env=build_env, add_headers=True)],
)
```

---

## Django (decorator + middleware)

Enable the middleware to inject a Guard:

```python
# settings.py
RBACX_GUARD_FACTORY = "rbacx_demo.rbacx_factory.build_guard"
MIDDLEWARE = [
    # ...
    "rbacx.adapters.django.middleware.RbacxDjangoMiddleware",
]
```

Use the decorator:

```python
from rbacx.adapters.django.decorators import require_access
from rbacx.core.model import Subject, Resource, Action, Context

def build_env(request):
    uid = getattr(getattr(request, "user", None), "id", None) or "anonymous"
    return Subject(id=str(uid), roles=["user"]), Action("read"), Resource(type="doc"), Context()

@require_access(build_env, add_headers=True)
def doc(request):
    ...
```

---

## Django REST Framework (permission)

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from rbacx.adapters.drf import make_permission
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

guard = Guard(policy)

def build_env(request):
    uid = getattr(getattr(request, "user", None), "username", None) or "anonymous"
    return Subject(id=uid, roles=["user"]), Action("read"), Resource(type="doc"), Context()

RBACXPermission = make_permission(guard, build_env, add_headers=True)

# Optionally attach headers on 403:
# REST_FRAMEWORK = {"EXCEPTION_HANDLER": "rbacx.adapters.drf.rbacx_exception_handler"}

class DocsView(APIView):
    permission_classes = [RBACXPermission]
    def get(self, request):
        return Response({"ok": True})
```
